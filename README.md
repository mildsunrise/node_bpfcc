# bpfcc

Node.js frontend (aka bindings) for iovisor's [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc).

**[💡 Examples](./examples)** &nbsp;•&nbsp; **[📚 API reference](https://bpfcc.alba.sh/docs/globals.html)**


## Usage

### Installing

First you need to [install BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system. You don't need to install everything, only the C library & development files; for instance, on Ubuntu the following should be enough:

~~~ bash
sudo apt install libbpfcc-dev
~~~

Then install this module and [`bpf`][], which is required as a peer dependency:

~~~ bash
npm install bpfcc bpf
~~~

### Loading & attaching programs

To use it, first pass your program to [`load`][] or [`loadSync`][] to compile it:

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

At a later point, if you no longer need it, you can use `bpf.detachAll()` to detach and unload everything from the kernel. If you don't, it might get called by the GC at some point, but it's not recommended to rely on this.

### Accessing maps

Once tracing has started, we can communicate with our eBPF program by accessing its maps (using the `get*Map` methods). In our case we have two array maps, with uint32 values:

~~~ typescript
const dist = bpf.getRawArrayMap('dist')
const distLinear = bpf.getRawArrayMap('dist_linear')

// Retrieve current values & parse them
const ys = [...dist].map(x => x.readUInt32LE(0))
console.log(ys)
~~~

`getRaw*Map` methods provide a raw interface which returns Buffers, so we had to parse the values ourselves. But there are also high-level versions that take a *conversion object*. For convenience, `bpf` provides a conversion for uint32, so we can write:

~~~ typescript
const { u32type } = require('bpf')

const dist = bpf.getArrayMap('dist', u32type)
const distLinear = bpf.getArrayMap('dist_linear', u32type)

console.log( [...dist] )
~~~

Refer to the [`bpf`][] module for details on the interface.

The full source code of this example is in [`bitehist.ts`](examples/bitehist.ts).
Remember you'll probably need root to run.


## Troubleshooting

Remember that not all features may be available in the kernel you are running, even if they're present in the API and typings. Trying to use a non-available feature will generally result in an `EINVAL` error.

A reference of eBPF features and minimum kernel versions required for them can be found **[here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)**.



[`bpf`]: https://github.com/mildsunrise/node_bpf
[`loadSync`]: https://bpfcc.alba.sh/docs/globals.html#loadsync
[`load`]: https://bpfcc.alba.sh/docs/globals.html#load
