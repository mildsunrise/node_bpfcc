# bpfcc

Node.JS frontend (aka bindings) for iovisor's [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc).

## Usage

First you need to [install BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system. You don't need to install everything, only the library & development files; for instance, on Ubuntu, the following should be enough:

~~~ bash
sudo apt install libbpfcc-dev
~~~

Then install this module:

~~~ bash
npm install bpfcc
~~~

And use it like this (you'll need root to run):

~~~ typescript
const bpf = require('bpfcc')

// TODO
~~~
