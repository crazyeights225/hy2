## Configuration Options:

In this document we describe the various configuration options available in our framework and their purpose. 
These fields and their values are stored in the profile file of each target program.

### Fields:

| Field | Description | Example |
|-------|-------------|---------|
| target | the name of the target | `ls` |
| target_path | The path to the target on the guest, or locally (default is `bins/<target>`) | `bins/ls` |
| process_name | the process name when the target is executed | `ls` |
| arch | The architecture of the guest on which to execute the target | `x86_64` |
| image_type | The guest image to use to execute the target | `generic` or `custom` |
| binary_type | (external, or built-in) specifies whether the target is on the guest | |
| target_type |  Specifies whether the target program is a library or an executable | |
| target_pages | The name of the target pages to analyze | `['ls']` |
| preconditions | Commands to run on the guest prior to executing the target | `['touch hello.txt']` |
| postconditions | Commands to run on the guest after executing the target | `['rm hello.txt']` |
| commands | (Only in individual input examples) The sequence of inputs to send to the target program | `[{'cmd': 'ls -lai', 'type': 'sync'}]` |
| inclusions | Optionally select a list of functions (by function name) to include in the analysis | `['main', 'ls_mode', ...]` |
| inclusions_named | A list of function name, page name pairs used to add additional functions from other pages into our analysis | `[["stpncpy", "libc-2.27.so"], ...]` |
| inclusion_paths | Pairs with inclusions_named,  a list of page name, file path pairs that indicates the path at which to find the executables associated with the additional pages included in the analysis | `{"libc-2.27.so": "/lib/x86_64-linux-gnu/libc-2.27.so", ...}` |
| exclusions |Optionally select a list of functions (by function name) that are out-of-scope | `['getfilecon', 'quoting_style_args']` |
| properties | specifies the set of properties to check against the target | |
| semantic_info | Allows you to give a specific meaning to variables which is used in specific properties. ie. This string holds a password, so we mark it as sensitive, and check it is not leaked. | `"SENSITIVE": {"attributes": {"dsource": "var.dsource", "fname": "var.fname"}, "conditions": [{"ls": "var.dsource", "op": "eq", "rs": "const.arg1"}, {"ls": "var.fname", "op": "eq", "rs": "const.string_eq"}]}` |

### Extensions:
- `enable_static_analysis` - (bool) - enables are optional static analysis step
- `enable_backedge_analysis` - (bool) - enables a back-edge analysis when building our program model (ie. it identifies loops)
- `enable_multithread_analysis` - (bool) - enables multi-thread analysis, models and analyzing the relationship between threads for programs that use multiple threads

Example:
```
{
    "target": "wget",
    "target_path": "wget.bin",
    "process_name": "wget.bin",
    "recording_name": "sample",
    "arch": "x86_64",
    "image_type": "generic",
    "bin_type": "extern",
    "exclusions": [],
    "type": "prog",
    "target_pages": "wget.bin",
    "inclusions_named": [["sym.iconv", "libc-2.27.so"], ["sym.pcre_exec", "libpcre.so.3"], ["sym.regexec", "libc-2.27.so"], ["sym.iconv_open", "libc-2.27.so"], ["sym.iconv_close", "libc-2.27.so"]],
    "inclusion_paths": {"libc-2.27.so": "/lib/x86_64-linux-gnu/libc-2.27.so", "libpcre.so.3": "/lib/x86_64-linux-gnu/libpcre.so.3"},
    "preconditions": [
        "panda.mount bins",
        "cp /root/bins/libnettle.so.7 /usr/lib/x86_64-linux-gnu/",
        "cd /root/bins/wget",
        "export PERL5LIB=/root/bins/wget"
    ],
    "postconditions": [],
    "command": [
        {
            "cmd": "./Test-iri.px",
            "type": "async"
        }
    ]
}
```