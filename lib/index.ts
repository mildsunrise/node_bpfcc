import { promisify } from 'util'
import {
    MapType, ProgramType, AttachType, MapRef, TypeConversion,
    RawMap, ConvMap, createMapRef,
    RawArrayMap, ConvArrayMap,
    RawQueueMap, ConvQueueMap,
} from 'bpf'

import { FD } from './util'
import { checkStatus } from './exception'

export { Code, BCCError } from './exception'

const native = require('../build/Release/bpfcc_binding')

// export const version: string = native.version

export interface USDT {
    pid?: number
    binaryPath?: string
    provider: string
    name: string
    probeFunc: string

    /**
     * When the kludge flag is set to 1 (default), we will only match on inode
     * when searching for modules in /proc/PID/maps that might contain the
     * tracepoint we're looking for.
     * By setting this to 0, we will match on both inode and
     * (dev_major, dev_minor), which is a more accurate way to uniquely
     * identify a file, but may fail depending on the filesystem backing the
     * target file (see bcc#2715)
     *
     * This hack exists because btrfs and overlayfs report different device
     * numbers for files in /proc/PID/maps vs stat syscall. Don't use it unless
     * you've had issues with inode collisions. Both btrfs and overlayfs are
     * known to require inode-only resolution to accurately match a file.
     *
     * set_probe_matching_kludge(0) must be called before USDTs are submitted to
     * BPF::init()
     */
    matchingKludge?: number
}

export enum ProbeAttachType {
    ENTRY,
    RETURN,
}

export interface Options {
    /** Module flags */
    flags?: number
    rwEngineEnabled?: boolean
    /** Map namespace */
    mapsNamespace?: string
    allowRlimit?: boolean

    /** Compilation flags */
    cflags?: string[]
    /** USDT probe definitions */
    usdt?: USDT[]

    /** Call [[autoload]] after loading the source (default: true) */
    autoload?: boolean
}

export const defaultOptions: Options = {
    flags: 0,
    rwEngineEnabled: native.rwEngineEnabled,
    mapsNamespace: "",
    allowRlimit: true,

    cflags: [],
    usdt: [],

    autoload: true,
}

/**
 * Description of an eBPF map from BCC
 * Should be compatible with `bpf.MapDesc`.
 */
export interface TableDesc {
    name: string
    fd: number

    type: MapType
    keySize: number
    valueSize: number
    maxEntries: number
    /**
     * Flags specified on map creation, see
     * [MapFlags](https://bpf.alba.sh/docs/enums/MapFlags.html)
     */
    flags: number
}

export interface BCCMapRef extends MapRef {
    /** Program to which this module belongs */
    bpf: BPFModule
}

const initSync = native.BPF.prototype.initSync
const initAsync = promisify(native.BPF.prototype.initAsync) // FIXME: does it work with 'this' bound?

function genericLoad(func: any, sync: boolean, program: string, options_?: Options) {
    const options = { ...defaultOptions, ...options_, program }
    const bpf_ = new native.BPF()
    const r = func.call(bpf_, options)
    return sync ? post(bpf_) : r.then(() => post(bpf_))
    function post(bpf_: any) {
        const bpf = new (BPFModule as any)(bpf_)
        if (options.autoload)
            bpf.autoload()
        return bpf
    }
}

/**
 * Compile a program and load it into the kernel.
 * 
 * **Note:** This is a heavy operation, use [[load]]
 * to avoid blocking the event loop.
 *
 * @param program C code to compile
 * @param options Additional options
 * @returns Loaded program instance
 */
export function loadSync(program: string, options?: Options): BPFModule {
    return genericLoad(initSync, true, program, options)
}

/**
 * Compile a program and load it into the kernel.
 *
 * @param program C code to compile
 * @param options Additional options
 * @returns Promise for loaded program instance
 */
export function load(program: string, options?: Options): Promise<BPFModule> {
    return genericLoad(initAsync, false, program, options)
}

function ksymname(name: string): bigint | undefined {
    return // TODO
}

function ksym(addr: bigint): string | undefined {
    return // TODO
}

export class BPFModule {
    private _bpf: any

    private constructor(_bpf: any) {
        this._bpf = _bpf
    }

    /**
     * Detach all functions & events.
     * 
     * @category Event attaching
     */
    detachAll() {
        return checkStatus(this._bpf.detachAll())
    }

    /**
     * @category Event attaching
     */
    attachKprobe(kernelFunc: string, probeFunc: string, options?: { kernelFuncOffset?: bigint, attachType?: ProbeAttachType, maxActive?: number }) {
        options = options || {}
        return checkStatus(this._bpf.attachKprobe(
            kernelFunc, probeFunc, options.kernelFuncOffset,
            options.attachType, options.maxActive
        ))
    }

    /**
     * @category Event attaching
     */
    detachKprobe(kernelFunc: string, options?: { attachType?: ProbeAttachType }) {
        options = options || {}
        return checkStatus(this._bpf.detachKprobe(kernelFunc, options.attachType))
    }

    /**
     * @category Event attaching
     */
    attachUprobe(binaryPath: string, symbol: string, probeFunc: string, options?: { symbolAddr?: bigint, attachType?: ProbeAttachType, pid?: number, symbolOffset?: bigint }) {
        options = options || {}
        return checkStatus(this._bpf.attachUprobe(
            binaryPath, symbol, probeFunc, options.symbolAddr,
            options.attachType, options.pid, options.symbolOffset
        ))
    }

    /**
     * @category Event attaching
     */
    detachUprobe(binaryPath: string, symbol: string, options?: { symbolAddr?: bigint, attachType?: ProbeAttachType, pid?: number, symbolOffset?: bigint }) {
        options = options || {}
        return checkStatus(this._bpf.detachUprobe(
            binaryPath, symbol, options.symbolAddr,
            options.attachType, options.pid, options.symbolOffset
        ))
    }

    /**
     * Convenience method, see [[attachKprobe]].
     * 
     * @category Event attaching
     */
    attachKretprobe(kernelFunc: string, probeFunc: string, options?: { kernelFuncOffset?: bigint, attachType?: ProbeAttachType, maxActive?: number }) {
        return this.attachKprobe(kernelFunc, probeFunc, { ...options, attachType: ProbeAttachType.RETURN })
    }

    /**
     * Convenience method, see [[detachKprobe]].
     * 
     * @category Event attaching
     */
    detachKretprobe(kernelFunc: string) {
        return this.detachKprobe(kernelFunc, { attachType: ProbeAttachType.RETURN })
    }

    /**
     * Convenience method, see [[attachUprobe]].
     * 
     * @category Event attaching
     */
    attachUretprobe(binaryPath: string, symbol: string, probeFunc: string, options?: { symbolAddr?: bigint, attachType?: ProbeAttachType, pid?: number, symbolOffset?: bigint }) {
        return this.attachUprobe(binaryPath, symbol, probeFunc, { ...options, attachType: ProbeAttachType.RETURN })
    }

    /**
     * Convenience method, see [[detachUprobe]].
     * 
     * @category Event attaching
     */
    detachUretprobe(binaryPath: string, symbol: string, options?: { symbolAddr?: bigint, attachType?: ProbeAttachType, pid?: number, symbolOffset?: bigint }) {
        return this.detachUprobe(binaryPath, symbol, { ...options, attachType: ProbeAttachType.RETURN })
    }

    /**
     * @category Event attaching
     */
    attachUsdt(usdt: USDT, options?: { pid?: number }) {
        options = options || {}
        return checkStatus(this._bpf.attachUsdt(usdt, options.pid))
    }

    /**
     * @category Event attaching
     */
    // attachUsdtAll() {
    //     return checkStatus(this._bpf.attachUsdtAll())
    // }

    /**
     * @category Event attaching
     */
    detachUsdt(usdt: USDT, options?: { pid?: number }) {
        options = options || {}
        return checkStatus(this._bpf.detachUsdt(usdt, options.pid))
    }

    /**
     * @category Event attaching
     */
    // detachUsdtAll() {
    //     return checkStatus(this._bpf.detachUsdtAll())
    // }

    /**
     * @category Event attaching
     */
    attachTracepoint(tracepoint: string, probeFunc: string) {
        return checkStatus(this._bpf.attachTracepoint(tracepoint, probeFunc))
    }

    /**
     * @category Event attaching
     */
    detachTracepoint(tracepoint: string) {
        return checkStatus(this._bpf.detachTracepoint(tracepoint))
    }

    /**
     * @category Event attaching
     */
    // attachRawTracepoint(tracepoint: string, probeFunc: string) {
    //     return checkStatus(this._bpf.attachRawTracepoint(tracepoint, probeFunc))
    // }

    /**
     * @category Event attaching
     */
    // detachRawTracepoint(tracepoint: string) {
    //     return checkStatus(this._bpf.detachRawTracepoint(tracepoint))
    // }

    /**
     * @category Event attaching
     */
    attachPerfEvent(evType: number, evConfig: number, probeFunc: string, samplePeriod: bigint, sampleFreq: bigint, options?: { pid?: number, cpu?: number, groupFd?: number }) {
        options = options || {}
        return checkStatus(this._bpf.attachPerfEvent(
            evType, evConfig, probeFunc,
            samplePeriod, sampleFreq, options.pid, options.cpu, options.groupFd
        ))
    }

    /**
     * @category Event attaching
     */
    detachPerfEvent(evType: number, evConfig: number) {
        return checkStatus(this._bpf.detachPerfEvent(evType, evConfig))
    }

    getSyscallFnName(name: string): string {
        return this._bpf.getSyscallFnName(name)
    }

    addModule(module: string) {
        if (!this._bpf.addModule(module))
            throw Error("Couldn't add module")
    }
    
    openPerfEvent(name: string, type: number, config: bigint) {
        return checkStatus(this._bpf.openPerfEvent(name, type, config))
    }

    closePerfEvent(name: string) {
        return checkStatus(this._bpf.closePerfEvent(name))
    }

    loadFunction(funcName: string, type: ProgramType): FD {
        const [ status, fd ] = this._bpf.loadFunction(funcName, type)
        checkStatus(status)
        return fd
    }

    unloadFunction(funcName: string) {
        return checkStatus(this._bpf.unloadFunction(funcName))
    }

    // attachFunction(programFd: FD, attachableFd: FD, attachType: AttachType, flags: bigint) {
    //     return checkStatus(this._bpf.attachFunction(programFd, attachableFd, attachType, flags))
    // }

    // detachFunction(programFd: FD, attachableFd: FD, attachType: AttachType) {
    //     return checkStatus(this._bpf.detachFunction(programFd, attachableFd, attachType))
    // }

    freeBccMemory() {
        // FIXME: better error checking?
        if (this._bpf.freeBccMemory())
            throw Error("Couldn't free memory")
    }

    /**
     * Retrieves all registered eBPF maps on this program
     * and their information, as a `(path, tableDesc)` dictionary.
     * See [[TableDesc]].
     */
    get maps(): Map<string, TableDesc> {
        return new Map(this._bpf.getMaps())
    }

    /**
     * Find the information of a map by name.
     * Returns undefined if the map is not found.
     * 
     * @param name Map name
     * @category Module info
     */
    findMap(name: string): TableDesc | undefined {
        return this._bpf.findMap(name)
    }

    /**
     * Retrieves all declared functions
     */
    get functions(): string[] {
        return this._bpf.getFunctions()
    }

    /**
     * Automatically load and attach functions beginning with
     * special prefixes (`kprobe__`, `tracepoint__`, etc.).
     * 
     * By default, this is automatically called by [[load]] or [[loadSync]].
     */
    autoload() {
        // Code adapted from the Python frontend //

        const syscallPrefixes = [
            'sys_',
            '__x64_sys_',
            '__x32_compat_sys_',
            '__ia32_compat_sys_',
            '__arm64_sys_',
            '__s390x_sys_',
            '__s390_sys_',
        ]

        // Find current system's syscall prefix by testing on the BPF syscall.
        // If no valid value found, will return the first possible value which
        // would probably lead to error in later API calls.
        function getSyscallPrefix() {
            for (const prefix of syscallPrefixes) {
                if (ksymname(prefix + 'bpf') !== undefined)
                    return prefix
            }
            return syscallPrefixes[0]
        }

        // Given a Kernel function name that represents a syscall but already has a
        // prefix included, transform it to current system's prefix. For example,
        // if "sys_clone" provided, the helper may translate it to "__x64_sys_clone".
        function fixSyscallFnname(x: string) {
            for (const prefix of syscallPrefixes) {
                if (x.startsWith(prefix))
                    return getSyscallPrefix() + x.substr(0, prefix.length)
            }
            return x
        }

        for (const fn of this.functions) {
            const m = /^(\w+)__(.+)$/.exec(fn)
            if (!m) continue
            const [, prefix, name] = m
            const prefixes: {[key: string]: () => void} = {
                kprobe: () => this.attachKprobe(fixSyscallFnname(name), fn),
                kretprobe: () => this.attachKretprobe(fixSyscallFnname(name), fn),
                tracepoint: () => this.attachTracepoint(name.replace(/__/g, ':'), fn),
                // raw_tracepoint: () => this.attachRawTracepoint(name, fn),
                // FIXME: kfunc & LSM support
            }
            if (Object.hasOwnProperty.call(prefixes, prefix))
                prefixes[prefix]()
        }
    }


    // MAP ACCESS

    /**
     * Creates and returns a custom
     * [MapRef](https://bpf.alba.sh/docs/interfaces/MapRef.html)
     * reference to the given map.
     * 
     * The reference doesn't support closing the FD, and
     * keeps the full BPF program alive for convenience.
     * 
     * @param name Map name
     * @category Map access
     */
    getMapRef(name: string): BCCMapRef {
        const desc = this.findMap(name)
        if (desc === undefined)
            throw Error(`No map named ${name} found`)
        // Use createMapRef to get info if available
        const ref = createMapRef(desc.fd, { parameters: desc })
        ref.close()
        // Make ref hold us alive, since we own the FD
        return Object.freeze({
            ...ref, fd: desc.fd, bpf: this,
            close() { throw Error('BCC refs do not support closing; use detachAll() to unload the program') }
        })
    }

    /**
     * Creates and returns a
     * [RawMap](https://bpf.alba.sh/docs/classes/RawMap.html)
     * instance to manipulate the given map.
     * 
     * @param name Map name
     * @category Map access
     */
    getRawMap(name: string) {
        return new RawMap(this.getMapRef(name))
    }

    /**
     * Creates and returns a generic
     * [IMap](https://bpf.alba.sh/docs/interfaces/IMap.html)
     * instance to manipulate the given map, using
     * the given
     * [conversions](https://bpf.alba.sh/docs/interfaces/TypeConversion.html)
     * for keys and values.
     * 
     * @param name Map name
     * @category Map access
     */
    getMap<K, V>(name: string, keyConv: TypeConversion<K>, valueConv: TypeConversion<V>) {
        return new ConvMap(this.getMapRef(name), keyConv, valueConv)
    }

    /**
     * Creates and returns a
     * [RawArrayMap](https://bpf.alba.sh/docs/classes/RawArrayMap.html)
     * instance to manipulate the given array map.
     * 
     * @param name Map name
     * @category Map access
     */
    getRawArrayMap(name: string) {
        return new RawArrayMap(this.getMapRef(name))
    }

    /**
     * Creates and returns a generic
     * [IArrayMap](https://bpf.alba.sh/docs/interfaces/IArrayMap.html)
     * instance to manipulate the given array map, using
     * the given
     * [conversion](https://bpf.alba.sh/docs/interfaces/TypeConversion.html)
     * for values.
     * 
     * @param name Map name
     * @category Map access
     */
    getArrayMap<V>(name: string, valueConv: TypeConversion<V>) {
        return new ConvArrayMap(this.getMapRef(name), valueConv)
    }

    /**
     * Creates and returns a
     * [RawQueueMap](https://bpf.alba.sh/docs/classes/RawQueueMap.html)
     * instance to manipulate the given queue or stack map.
     * 
     * @param name Map name
     * @category Map access
     */
    getRawQueueMap(name: string) {
        return new RawQueueMap(this.getMapRef(name))
    }

    /**
     * Creates and returns a generic
     * [IQueueMap](https://bpf.alba.sh/docs/interfaces/IQueueMap.html)
     * instance to manipulate the given queue or stack map, using
     * the given
     * [conversion](https://bpf.alba.sh/docs/interfaces/TypeConversion.html)
     * for values.
     * 
     * @param name Map name
     * @category Map access
     */
    getQueueMap<V>(name: string, valueConv: TypeConversion<V>) {
        return new ConvQueueMap(this.getMapRef(name), valueConv)
    }
}
