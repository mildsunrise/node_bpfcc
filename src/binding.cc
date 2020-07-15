#include <bcc/bcc_version.h>
#include <bcc/BPF.h>

#if defined(__GNUC__) && __GNUC__ >= 8
#define DISABLE_WCAST_FUNCTION_TYPE _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wcast-function-type\"")
#define DISABLE_WCAST_FUNCTION_TYPE_END _Pragma("GCC diagnostic pop")
#else
#define DISABLE_WCAST_FUNCTION_TYPE
#define DISABLE_WCAST_FUNCTION_TYPE_END
#endif

DISABLE_WCAST_FUNCTION_TYPE
#include <nan.h>
DISABLE_WCAST_FUNCTION_TYPE_END
#include <uv.h>


NAN_MODULE_INIT(Init) {
    // TODO
}

DISABLE_WCAST_FUNCTION_TYPE
NODE_MODULE(bpfcc_binding, Init)
DISABLE_WCAST_FUNCTION_TYPE_END
