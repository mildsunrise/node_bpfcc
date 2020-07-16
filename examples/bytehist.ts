import { loadSync } from '..'

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

console.log('Tracing...')
setInterval(() => {
    // TODO: print histogram
}, 2000)
