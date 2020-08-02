const native = require('../build/Release/bpfcc_binding')

export const version: string = native.version

import { checkStatus } from './exception'
export { Code, BCCError } from './exception'

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
}
