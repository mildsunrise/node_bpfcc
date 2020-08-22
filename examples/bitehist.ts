/** Block I/O size histogram */

import { loadSync } from '..'
import { u32type } from 'bpf'

// Upload BPF to kernel
console.log('Loading program...')
const bpf = loadSync(`
    #include <uapi/linux/ptrace.h>
    #include <linux/blkdev.h>

    BPF_HISTOGRAM(dist);
    BPF_HISTOGRAM(dist_linear);

    int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req) {
        dist.increment(bpf_log2l(req->__data_len / 1024));
        dist_linear.increment(req->__data_len / 1024);
        return 0;
    }
`)

console.log('Done! Tracing...')
const dist = bpf.getArrayMap('dist', u32type)
setInterval(() => {
    const ys = [...dist]
    const maxY = Math.max(...ys)
    const cols = 68
    const rpad = (x: string, n: number) => ' '.repeat(Math.max(n - x.length, 0)) + x.substr(0, n)
    console.log('\nDistribution:\n' + ys.map((y, i) =>
        rpad(`${y}`, 8) + ' |' + '#'.repeat(Math.round(y / maxY * cols))
    ).join('\n'))
}, 2000)
