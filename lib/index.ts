const native = require('../build/Release/bpfcc_binding')

export const version: string = native.version

import { FD } from './util'
import { checkStatus } from './exception'
import { ProgramType, AttachType } from './enums'

export { Code, BCCError } from './exception'
export { ProgramType, MapType } from './enums'

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
    /** Compilation flags */
    cflags?: string[]
    /** USDT probe definitions */
    usdt?: USDT[]
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
	/** Flags specified on map creation, see [[MapFlags]] */
	flags: number
}

export interface FunctionDesc {
    addr: bigint
    size: bigint
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
export function loadSync(program: string, options?: Options) {
    options = options || {}
    const bpf = new BPF()
    bpf.initSync(program, options.cflags || [], options.usdt || [])
    return bpf
}

/**
 * Compile a program and load it into the kernel.
 *
 * @param program C code to compile
 * @param options Additional options
 * @returns Promise for loaded program instance
 */
export function load(program: string, options?: Options) {
    options = options || {}
    const bpf = new BPF()
    return bpf.init(program, options.cflags || [], options.usdt || [])
        .then(() => bpf)
}

export class BPF {
    private _bpf: any

    /**
     * Constructs an unloaded program holder.
     * Most users will want [[load]] or [[loadSync]] instead.
     */
    constructor() {
        this._bpf = new native.BPF()
    }

    /**
     * (Internal function, use [[loadSync]] instead)
     */
    initSync(program: string, cflags: string[], usdt: USDT[]) {
        return checkStatus(this._bpf.initSync(program, cflags, usdt))
    }

    /**
     * (Internal function, use [[load]] instead)
     */
    init(program: string, cflags: string[], usdt: USDT[]) {
        return new Promise(resolve =>
            this._bpf.initAsync(resolve, program, cflags, usdt)
        ).then(checkStatus)
    }

    initUsdt(usdt: USDT) {
        return checkStatus(this._bpf.initUsdt(usdt))
    }

    detachAll() {
        return checkStatus(this._bpf.detachAll())
    }

    attachKprobe(kernelFunc: string, probeFunc: string, options?: { kernelFuncOffset?: bigint, attachType?: ProbeAttachType, maxActive?: number }) {
        options = options || {}
        return checkStatus(this._bpf.attachKprobe(
            kernelFunc, probeFunc, options.kernelFuncOffset,
            options.attachType, options.maxActive
        ))
    }

    detachKprobe(kernelFunc: string, options?: { attachType?: ProbeAttachType }) {
        options = options || {}
        return checkStatus(this._bpf.detachKprobe(kernelFunc, options.attachType))
    }

    attachUprobe(binaryPath: string, symbol: string, probeFunc: string, options?: { symbolAddr?: bigint, attachType?: ProbeAttachType, pid?: number, symbolOffset?: bigint }) {
        options = options || {}
        return checkStatus(this._bpf.attachUprobe(
            binaryPath, symbol, probeFunc, options.symbolAddr,
            options.attachType, options.pid, options.symbolOffset
        ))
    }

    detachUprobe(binaryPath: string, symbol: string, options?: { symbolAddr?: bigint, attachType?: ProbeAttachType, pid?: number, symbolOffset?: bigint }) {
        options = options || {}
        return checkStatus(this._bpf.detachUprobe(
            binaryPath, symbol, options.symbolAddr,
            options.attachType, options.pid, options.symbolOffset
        ))
    }

    attachUsdt(usdt: USDT, options?: { pid?: number }) {
        options = options || {}
        return checkStatus(this._bpf.attachUsdt(usdt, options.pid))
    }

    attachUsdtAll() {
        return checkStatus(this._bpf.attachUsdtAll())
    }

    detachUsdt(usdt: USDT, options?: { pid?: number }) {
        options = options || {}
        return checkStatus(this._bpf.detachUsdt(usdt, options.pid))
    }

    detachUsdtAll() {
        return checkStatus(this._bpf.detachUsdtAll())
    }

    attachTracepoint(tracepoint: string, probeFunc: string) {
        return checkStatus(this._bpf.attachTracepoint(tracepoint, probeFunc))
    }

    detachTracepoint(tracepoint: string) {
        return checkStatus(this._bpf.detachTracepoint(tracepoint))
    }

    attachRawTracepoint(tracepoint: string, probeFunc: string) {
        return checkStatus(this._bpf.attachRawTracepoint(tracepoint, probeFunc))
    }

    detachRawTracepoint(tracepoint: string) {
        return checkStatus(this._bpf.detachRawTracepoint(tracepoint))
    }

    attachPerfEvent(evType: number, evConfig: number, probeFunc: string, samplePeriod: bigint, sampleFreq: bigint, options?: { pid?: number, cpu?: number, groupFd?: number }) {
        options = options || {}
        return checkStatus(this._bpf.attachPerfEvent(
            evType, evConfig, probeFunc,
            samplePeriod, sampleFreq, options.pid, options.cpu, options.groupFd
        ))
    }

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

    attachFunction(programFd: FD, attachableFd: FD, attachType: AttachType, flags: bigint) {
        return checkStatus(this._bpf.attachFunction(programFd, attachableFd, attachType, flags))
    }

    detachFunction(programFd: FD, attachableFd: FD, attachType: AttachType) {
        return checkStatus(this._bpf.detachFunction(programFd, attachableFd, attachType))
    }

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
     */
    findMap(name: string): TableDesc | undefined {
        return this._bpf.findMap(name)
    }

    /**
     * Creates and returns a [[RawMap]] instance to manipulate
     * the given map.
     * 
     * @param name Map name
     */
    getRawMap(name: string) {
        const desc = this.findMap(name)
        if (desc === undefined)
            throw Error(`No map named ${name} found`)
        // Have Map hold us alive, since we own the FD
        ; (desc as any).bpf = this
        return new RawMap(desc.fd, desc)
    }

    /**
     * Retrieves all loaded functions
     */
    get functions(): Map<string, FunctionDesc> {
        return new Map(this._bpf.getFunctions())
    }
}
