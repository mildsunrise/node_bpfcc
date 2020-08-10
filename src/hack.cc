#include <cctype>
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>

#include <bcc/BPFTable.h>
#include <bcc/bcc_exception.h>
#include <bcc/bcc_syms.h>
#include <bcc/bpf_module.h>
#include "linux/bpf.h"
#include <bcc/libbpf.h>
#include <bcc/table_storage.h>

// ebpf::BPF doesn't expose the underlying BPFModule, and we
// *need* to access it. It leaves no other option...
#define private public
#include <bcc/BPF.h>

ebpf::BPFModule* getModule(ebpf::BPF& bpf) {
    return bpf.bpf_module_.get();
}
