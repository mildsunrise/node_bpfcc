#include <bcc/bcc_version.h>
#include <bcc/BPF.h>

#include <napi.h>

using Napi::CallbackInfo;


Napi::Value WrapStatus(Napi::Env env, ebpf::StatusTuple status) {
    if (status.ok())
        return env.Null();
    Napi::Object ret = Napi::Object::New(env);
    ret.Set("code", Napi::Number::New(env, (double) status.code()));
    ret.Set("msg", Napi::String::New(env, status.msg()));
    return ret;
}

ebpf::USDT _ParseUSDT(Napi::Env env, Napi::Object obj) {
    Napi::String provider (env, obj.Get("provider"));
    Napi::String name (env, obj.Get("name"));
    Napi::String probe_func (env, obj.Get("probeFunc"));
    if (obj.Has("pid") && obj.Has("binaryPath")) {
        Napi::String binary_path (env, obj.Get("binaryPath"));
        Napi::Number pid (env, obj.Get("pid"));
        return ebpf::USDT(binary_path, pid, provider, name, probe_func);
    } else if (obj.Has("pid")) {
        Napi::Number pid (env, obj.Get("pid"));
        return ebpf::USDT(pid, provider, name, probe_func);
    } else if (obj.Has("binaryPath")) {
        Napi::String binary_path (env, obj.Get("binaryPath"));
        return ebpf::USDT(binary_path, provider, name, probe_func);
    }
    throw Napi::Error::New(env, "USDT probe must supply pid or binaryPath");
}

ebpf::USDT ParseUSDT(Napi::Env env, Napi::Object obj) {
    ebpf::USDT usdt = _ParseUSDT(env, obj);
    if (obj.Has("matchingKludge")) {
        Napi::Number kludge (env, obj.Get("matchingKludge"));
        int ret = usdt.set_probe_matching_kludge(kludge.Int32Value());
        if (ret)
            throw Napi::Error::New(env, "Invalid value for matchingKludge");
    }
    return usdt;
}

class BPF : public Napi::ObjectWrap<BPF> {
  public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "BPF", {
            InstanceMethod<&BPF::InitBPF>("init"),
        });
        Napi::FunctionReference* constructor = new Napi::FunctionReference();
        *constructor = Napi::Persistent(func);
        exports.Set("BPF", func);
        env.SetInstanceData<Napi::FunctionReference>(constructor);
        return exports;
    }

    BPF(const CallbackInfo& info) : Napi::ObjectWrap<BPF>(info) {}

  private:
    ebpf::BPF bpf;

    Napi::Value InitBPF(const CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() != 3 || !info[0].IsString() || !info[1].IsArray() || !info[2].IsArray())
            throw Napi::TypeError::New(env, "Invalid arguments");
        Napi::String program (env, info[0]);
        Napi::Array cflags (env, info[1]);
        Napi::Array usdt (env, info[2]);

        std::vector<std::string> cflags_;
        for (size_t i = 0; i < cflags.Length(); i++) {
            cflags_.push_back(Napi::String(env, cflags.Get(i)));
        }
        std::vector<ebpf::USDT> usdt_;
        for (size_t i = 0; i < usdt.Length(); i++) {
            Napi::Object item (env, usdt.Get(i));
            usdt_.push_back(ParseUSDT(env, item));
        }
        return WrapStatus(env, bpf.init(program, cflags_, usdt_));
    }
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("version", Napi::String::New(env, LIBBCC_VERSION));
    BPF::Init(env, exports);
    return exports;
}

NODE_API_MODULE(bpfcc_binding, Init)
