#include <memory>
#include <vector>
#include <string>

//#include <bcc/bcc_version.h>
#include <bcc/BPF.h>

#include <napi.h>

#include "hack.h"

using Napi::CallbackInfo;
using ebpf::StatusTuple;


std::string GetString(Napi::Env env, Napi::Value value) {
    if (!value.IsString())
        throw Napi::TypeError::New(env, "String expected");
    return Napi::String(env, value);
}

template<class T>
T GetNumber(Napi::Env env, Napi::Value value) {
    return Napi::Number(env, value);
}

template<class T>
T GetNumber(Napi::Env env, Napi::Value value, T def) {
    return value.IsUndefined() ? def : GetNumber<T>(env, value);
}

bool GetBoolean(Napi::Env env, Napi::Value value) {
    return Napi::Boolean(env, value);
}

bpf_probe_attach_type GetAttachType(Napi::Env env, Napi::Value value) {
    return (bpf_probe_attach_type) GetNumber<int>(env, value, (int) BPF_PROBE_ENTRY);
}

uint64_t GetUint64(Napi::Env env, Napi::Value value) {
    bool lossless;
    uint64_t result = Napi::BigInt(env, value).Uint64Value(&lossless);
    if (!lossless)
        throw Napi::RangeError::New(env, "Bigint outside uint64_t range");
    return result;
}

uint64_t GetUint64(Napi::Env env, Napi::Value value, uint64_t def) {
    // FIXME: verify that info[234] returns an empty Napi::Value
    return value.IsUndefined() ? def : GetUint64(env, value);
}


Napi::Value WrapStatus(Napi::Env env, StatusTuple status) {
    if (status.ok())
        return env.Null();
    auto ret = Napi::Object::New(env);
    ret["code"] = Napi::Number::New(env, (double) status.code());
    ret["msg"] = Napi::String::New(env, status.msg());
    return ret;
}

Napi::Value FormatTableDesc(Napi::Env env, const ebpf::TableDesc& desc) {
    auto ret = Napi::Object::New(env);
    ret["name"] = Napi::String::New(env, desc.name);
    ret["fd"] = Napi::Number::New(env, desc.fd);
    ret["type"] = Napi::Number::New(env, desc.type);
    ret["keySize"] = Napi::Number::New(env, desc.key_size);
    ret["valueSize"] = Napi::Number::New(env, desc.leaf_size);
    ret["maxEntries"] = Napi::Number::New(env, desc.max_entries);
    ret["flags"] = Napi::Number::New(env, desc.flags);
    return ret;
}

ebpf::USDT _ParseUSDT(Napi::Env env, Napi::Object obj) {
    auto provider = GetString(env, obj["provider"]);
    auto name = GetString(env, obj["name"]);
    auto probe_func = GetString(env, obj["probeFunc"]);
    if (obj.Has("pid") && obj.Has("binaryPath")) {
        auto binary_path = GetString(env, obj["binaryPath"]);
        auto pid = GetNumber<pid_t>(env, obj["pid"]);
        return ebpf::USDT(binary_path, pid, provider, name, probe_func);
    } else if (obj.Has("pid")) {
        auto pid = GetNumber<pid_t>(env, obj["pid"]);
        return ebpf::USDT(pid, provider, name, probe_func);
    } else if (obj.Has("binaryPath")) {
        auto binary_path = GetString(env, obj["binaryPath"]);
        return ebpf::USDT(binary_path, provider, name, probe_func);
    }
    throw Napi::Error::New(env, "USDT probe must supply pid or binaryPath");
}

ebpf::USDT ParseUSDT(Napi::Env env, Napi::Value x) {
    Napi::Object obj (env, x);
    auto usdt = _ParseUSDT(env, obj);
    if (obj.Has("matchingKludge")) {
        auto kludge = GetNumber<int>(env, obj["matchingKludge"]);
        int ret = usdt.set_probe_matching_kludge(kludge);
        if (ret)
            throw Napi::Error::New(env, "Invalid value for matchingKludge");
    }
    return usdt;
}


class BPF : public Napi::ObjectWrap<BPF> {
  public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "BPF", {
            InstanceMethod<&BPF::InitSync>("initSync"),
            InstanceMethod<&BPF::InitAsync>("initAsync"),

            InstanceMethod<&BPF::DetachAll>("detachAll"),

            InstanceMethod<&BPF::AttachKprobe>("attachKprobe"),
            InstanceMethod<&BPF::DetachKprobe>("detachKprobe"),

            InstanceMethod<&BPF::AttachUprobe>("attachUprobe"),
            InstanceMethod<&BPF::DetachUprobe>("detachUprobe"),
            InstanceMethod<&BPF::AttachUsdt>("attachUsdt"),
            InstanceMethod<&BPF::AttachUsdtAll>("attachUsdtAll"),
            InstanceMethod<&BPF::DetachUsdt>("detachUsdt"),
            InstanceMethod<&BPF::DetachUsdtAll>("detachUsdtAll"),

            InstanceMethod<&BPF::AttachTracepoint>("attachTracepoint"),
            InstanceMethod<&BPF::DetachTracepoint>("detachTracepoint"),

            InstanceMethod<&BPF::AttachRawTracepoint>("attachRawTracepoint"),
            InstanceMethod<&BPF::DetachRawTracepoint>("detachRawTracepoint"),

            InstanceMethod<&BPF::AttachPerfEvent>("attachPerfEvent"),
            //InstanceMethod<&BPF::AttachPerfEventRaw>("attachPerfEventRaw"),
            InstanceMethod<&BPF::DetachPerfEvent>("detachPerfEvent"),
            //InstanceMethod<&BPF::DetachPerfEventRaw>("detachPerfEventRaw"),
            InstanceMethod<&BPF::GetSyscallFnName>("getSyscallFnName"),

            InstanceMethod<&BPF::AddModule>("addModule"),

            InstanceMethod<&BPF::OpenPerfEvent>("openPerfEvent"),
            InstanceMethod<&BPF::ClosePerfEvent>("closePerfEvent"),
            
            InstanceMethod<&BPF::LoadFunction>("loadFunction"),
            InstanceMethod<&BPF::UnloadFunction>("unloadFunction"),
            InstanceMethod<&BPF::AttachFunction>("attachFunction"),
            InstanceMethod<&BPF::DetachFunction>("detachFunction"),

            InstanceMethod<&BPF::FreeBccMemory>("freeBccMemory"),

            // Map related
            InstanceMethod<&BPF::GetMaps>("getMaps"),
            InstanceMethod<&BPF::FindMap>("findMap"),

            InstanceMethod<&BPF::GetFunctions>("getFunctions"),
        });
        Napi::FunctionReference* constructor = new Napi::FunctionReference();
        *constructor = Napi::Persistent(func);
        exports["BPF"] = func;
        env.SetInstanceData<Napi::FunctionReference>(constructor);
        return exports;
    }

    BPF(const CallbackInfo& info) : Napi::ObjectWrap<BPF>(info) {}

  private:

    // INITIALIZATION

    std::unique_ptr<ebpf::BPF> bpf;
    
    struct InitOptions {
        // module creation options
        unsigned int flags;
        bool rw_engine_enabled;
        std::string maps_ns;
        bool allow_rlimit;

        // loading options
        std::string program;
        std::vector<std::string> cflags;
        std::vector<ebpf::USDT> usdt;

        void parse(Napi::Env env, Napi::Value options) {
            Napi::Object obj (env, options);
            flags = GetNumber<uint32_t>(env, obj["flags"]);
            rw_engine_enabled = GetBoolean(env, obj["rwEngineEnabled"]);
            maps_ns = GetString(env, obj["mapsNamespace"]);
            allow_rlimit = GetBoolean(env, obj["allowRlimit"]);
            program = GetString(env, obj["program"]);
            Napi::Array cflags (env, Napi::Value(obj["cflags"]));
            for (size_t i = 0, length = cflags.Length(); i < length; i++)
                this->cflags.push_back(GetString(env, cflags[i]));
            Napi::Array usdt (env, Napi::Value(obj["usdt"]));
            for (size_t i = 0, length = usdt.Length(); i < length; i++)
                this->usdt.push_back(ParseUSDT(env, usdt[i]));
        }
    };

    StatusTuple init(InitOptions& options) {
        // FIXME: expose dev_name as option?
        auto bpf = std::make_unique<ebpf::BPF>(options.flags, nullptr, options.rw_engine_enabled, options.maps_ns, options.allow_rlimit);
        auto status = bpf->init(options.program, options.cflags, options.usdt);
        if (status.ok())
            this->bpf = std::move(bpf);
        return status;
    }

    class InitWorker : public Napi::AsyncWorker {
      public:
        InitWorker(BPF& bpf, InitOptions& options, Napi::Function& callback)
            : AsyncWorker(bpf.Value(), callback, "bpfcc.load"),
            bpf(bpf), options(options), status(StatusTuple::OK()) {}

        BPF& bpf;
        InitOptions options;
        StatusTuple status;
        
        void Execute() override {
            status = bpf.init(options);
        }

        void OnOK() override {
            Napi::HandleScope scope(Env());
            Callback().Call({ WrapStatus(Env(), status) });
        }
    };

    void InitAsync(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        InitOptions options;
        options.parse(env, info[0]);
        Napi::Function callback (env, info[1]);
        (new InitWorker(*this, options, callback))->Queue();
    }

    Napi::Value InitSync(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        InitOptions options;
        options.parse(env, info[0]);
        return WrapStatus(env, this->init(options));
    }


    // ATTACH / DETACH

    Napi::Value DetachAll(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        return WrapStatus(env, bpf->detach_all());
    }

    Napi::Value AttachKprobe(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto kernel_func = GetString(env, info[a++]);
        auto probe_func = GetString(env, info[a++]);
        auto kernel_func_offset = GetUint64(env, info[a++], 0);
        auto attach_type = GetAttachType(env, info[a++]);
        auto maxactive = GetNumber<int>(env, info[a++], 0);
        return WrapStatus(env, bpf->attach_kprobe(
            kernel_func, probe_func, kernel_func_offset,
            attach_type, maxactive
        ));
    }

    Napi::Value DetachKprobe(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto kernel_func = GetString(env, info[a++]);
        auto attach_type = GetAttachType(env, info[a++]);
        return WrapStatus(env, bpf->detach_kprobe(kernel_func, attach_type));
    }

    Napi::Value AttachUprobe(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto binary_path = GetString(env, info[a++]);
        auto symbol = GetString(env, info[a++]);
        auto probe_func = GetString(env, info[a++]);
        auto symbol_addr = GetUint64(env, info[a++], 0);
        auto attach_type = GetAttachType(env, info[a++]);
        auto pid = GetNumber<pid_t>(env, info[a++], -1);
        auto symbol_offset = GetUint64(env, info[a++], 0);
        return WrapStatus(env, bpf->attach_uprobe(
            binary_path, symbol, probe_func, symbol_addr,
            attach_type, pid, symbol_offset
        ));
    }

    Napi::Value DetachUprobe(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto binary_path = GetString(env, info[a++]);
        auto symbol = GetString(env, info[a++]);
        auto symbol_addr = GetUint64(env, info[a++], 0);
        auto attach_type = GetAttachType(env, info[a++]);
        auto pid = GetNumber<pid_t>(env, info[a++], -1);
        auto symbol_offset = GetUint64(env, info[a++], 0);
        return WrapStatus(env, bpf->detach_uprobe(
            binary_path, symbol, symbol_addr,
            attach_type, pid, symbol_offset
        ));
    }

    Napi::Value AttachUsdt(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto usdt = ParseUSDT(env, Napi::Object(env, info[a++]));
        auto pid = GetNumber<pid_t>(env, info[a++], -1);
        return WrapStatus(env, bpf->attach_usdt(usdt, pid));
    }

    Napi::Value AttachUsdtAll(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        return WrapStatus(env, bpf->attach_usdt_all());
    }

    Napi::Value DetachUsdt(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto usdt = ParseUSDT(env, Napi::Object(env, info[a++]));
        auto pid = GetNumber<pid_t>(env, info[a++], -1);
        return WrapStatus(env, bpf->detach_usdt(usdt, pid));
    }

    Napi::Value DetachUsdtAll(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        return WrapStatus(env, bpf->detach_usdt_all());
    }

    Napi::Value AttachTracepoint(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto tracepoint = GetString(env, info[a++]);
        auto probe_func = GetString(env, info[a++]);
        return WrapStatus(env, bpf->attach_tracepoint(tracepoint, probe_func));
    }

    Napi::Value DetachTracepoint(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto tracepoint = GetString(env, info[a++]);
        return WrapStatus(env, bpf->detach_tracepoint(tracepoint));
    }

    Napi::Value AttachRawTracepoint(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto tracepoint = GetString(env, info[a++]);
        auto probe_func = GetString(env, info[a++]);
        return WrapStatus(env, bpf->attach_raw_tracepoint(tracepoint, probe_func));
    }

    Napi::Value DetachRawTracepoint(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto tracepoint = GetString(env, info[a++]);
        return WrapStatus(env, bpf->detach_raw_tracepoint(tracepoint));
    }

    Napi::Value AttachPerfEvent(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto ev_type = GetNumber<uint32_t>(env, info[a++]);
        auto ev_config = GetNumber<uint32_t>(env, info[a++]);
        auto probe_func = GetString(env, info[a++]);
        auto sample_period = GetUint64(env, info[a++]);
        auto sample_freq = GetUint64(env, info[a++]);
        auto pid = GetNumber<pid_t>(env, info[a++], -1);
        auto cpu = GetNumber<int>(env, info[a++], -1);
        auto group_fd = GetNumber<int>(env, info[a++], -1);
        return WrapStatus(env, bpf->attach_perf_event(
            ev_type, ev_config, probe_func,
            sample_period, sample_freq, pid, cpu, group_fd
        ));
    }

    Napi::Value DetachPerfEvent(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto ev_type = GetNumber<uint32_t>(env, info[a++]);
        auto ev_config = GetNumber<uint32_t>(env, info[a++]);
        return WrapStatus(env, bpf->detach_perf_event(ev_type, ev_config));
    }


    // OTHER

    Napi::Value GetSyscallFnName(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto name = GetString(env, info[a++]);
        return Napi::String::New(env, bpf->get_syscall_fnname(name));
    }

    Napi::Value AddModule(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto module = GetString(env, info[a++]);
        return Napi::Boolean::New(env, bpf->add_module(module));
    }

    Napi::Value OpenPerfEvent(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto name = GetString(env, info[a++]);
        auto type = GetNumber<uint32_t>(env, info[a++]);
        auto config = GetUint64(env, info[a++]);
        return WrapStatus(env, bpf->open_perf_event(name, type, config));
    }

    Napi::Value ClosePerfEvent(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto name = GetString(env, info[a++]);
        return WrapStatus(env, bpf->close_perf_event(name));
    }

    // FIXME: expose perf buffer (open / close / get / poll)

    Napi::Value FreeBccMemory(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        return Napi::Number::New(env, bpf->free_bcc_memory());
    }


    // FUNCTION LOADING

    Napi::Value LoadFunction(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto func_name = GetString(env, info[a++]);
        auto type = (enum bpf_prog_type) GetNumber<uint32_t>(env, info[a++]);

        int fd = -1;
        auto ret = Napi::Array::New(env);
        ret[0U] = WrapStatus(env, bpf->load_func(func_name, type, fd));
        ret[1U] = Napi::Number::New(env, fd);
        return ret;
    }

    Napi::Value UnloadFunction(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto func_name = GetString(env, info[a++]);
        return WrapStatus(env, bpf->unload_func(func_name));
    }

    Napi::Value AttachFunction(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto prog_fd = GetNumber<uint32_t>(env, info[a++]);
        auto attachable_fd = GetNumber<uint32_t>(env, info[a++]);
        auto attach_type = (enum bpf_attach_type) GetNumber<uint32_t>(env, info[a++]);
        auto flags = GetUint64(env, info[a++]);
        return WrapStatus(env, bpf->attach_func(prog_fd, attachable_fd, attach_type, flags));
    }

    Napi::Value DetachFunction(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto prog_fd = GetNumber<uint32_t>(env, info[a++]);
        auto attachable_fd = GetNumber<uint32_t>(env, info[a++]);
        auto attach_type = (enum bpf_attach_type) GetNumber<uint32_t>(env, info[a++]);
        return WrapStatus(env, bpf->detach_func(prog_fd, attachable_fd, attach_type));
    }


    // MODULE INFO

    Napi::Value GetMaps(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        auto ret = Napi::Array::New(env);
        size_t count = 0;
        auto& ts = getModule(*bpf)->table_storage();
        for (auto i = ts.begin(); i != ts.end(); ++i) {
            auto item = Napi::Array::New(env, 2);
            item[0U] = Napi::String::New(env, i->first);
            item[1U] = FormatTableDesc(env, i->second);
            ret[count++] = item;
        }
        return ret;
    }

    Napi::Value FindMap(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        size_t a = 0;
        auto name = GetString(env, info[a++]);

        ebpf::TableStorage::iterator it;
        auto& ts = getModule(*bpf)->table_storage();
        if (ts.Find(ebpf::Path({getModule(*bpf)->id(), name}), it))
            return FormatTableDesc(env, it->second);
        return env.Undefined();
    }

    Napi::Value GetFunctions(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        auto bpf_module = getModule(*bpf);
        auto count = bpf_module->num_functions();
        auto ret = Napi::Array::New(env, count);
        for (size_t i = 0; i < count; i++)
            ret[i] = Napi::String::New(env, bpf_module->function_name(i));
        return ret;
    }

};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    //exports["version"] = Napi::String::New(env, LIBBCC_VERSION);
    exports["rwEngineEnabled"] = Napi::Boolean::New(env, ebpf::bpf_module_rw_engine_enabled());
    BPF::Init(env, exports);
    return exports;
}

NODE_API_MODULE(bpfcc_binding, Init)
