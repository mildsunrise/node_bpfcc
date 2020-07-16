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

export interface Options {
    cflags?: string[]
    usdt?: USDT[]
}

export class BPF {
    private _bpf: any
    constructor() {
        this._bpf = new native.BPF()
    }
    init(program: string, cflags: string[], usdt: USDT[]) {
        return checkStatus(this._bpf.init(program, cflags, usdt))
    }

}

export function init(program: string, options?: Options) {
    options = options || {}
    const bpf = new BPF()
    bpf.init(program, options.cflags || [], options.usdt || [])
    return bpf
}
