# bpfcc

Node.JS frontend (aka bindings) for iovisor's [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc).

## Usage

First you need to [install BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system. You don't need to install everything, only the C library & development files; for instance, on Ubuntu, the following should be enough:

~~~ bash
sudo apt install libbpfcc-dev
~~~

Then install this module and [`bpf`][], which is required as a peer dependency:

~~~ bash
npm install bpfcc bpf
~~~

To use it, first pass your program to `loadSync` or `load` to compile it:

~~~ typescript
const { loadSync } = require('bpfcc')

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
~~~

Then you need to load & attach your functions to kernel events using
the `attach*` methods:

~~~ typescript
bpf.attachKprobe('blk_account_io_done', 'kprobe__blk_account_io_done')
~~~

**Note:** By default, functions starting with prefixes like `kprobe__` are automatically detected and attached, so the above isn't necessary in this case.

Once tracing has started, we can communicate with our eBPF program by accessing the maps (using the `get*Map` methods). In our case we have two array maps:

~~~ typescript
const dist = bpf.getRawArrayMap('dist')
const distLinear = bpf.getRawArrayMap('dist_linear')

// Retrieve current values & parse them
const ys = [...dist].map(x => x.readUInt32LE(0))
console.log(ys)
~~~

Refer to the [bpf](https://github.com/mildsunrise/node_bpf) module for details on the interface.

The full source code of this example is in [`bitehist.ts`](examples/bitehist.ts).
Remember you'll probably need root to run.

A reference of eBPF features and minimum kernel versions required for them can be found in:
https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md



[`bpf`]: https://github.com/mildsunrise/node_bpf
