{
    "targets": [
        {
            "target_name": "bpfcc_binding",
            "sources": [ "src/binding.cc" ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")"
            ]
        }
    ],
}
