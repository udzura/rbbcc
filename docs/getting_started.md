# Getting Started

RbBCC is a project to utilize the power of eBPF/BCC from Ruby.

## Setup

RbBCC requires `libbcc.so` version **0.10.0**(we plan to support newer version of libbcc, but it may be done after rbbcc 1.0...).

BTW we do not need to install header files, becuase current version of RbBCC uses the functionality of libbcc via ffi(We use MRI's standard library **fiddle**, not external gems).

We can install this shared library via package `libbcc` from official iovisor project repo:

```console
# e.g. In Ubuntu:
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
$ echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
$ sudo apt-get update
$ sudo apt-get install libbcc
```

For more imformation, see [bcc's official doc](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

After installed libbcc, you can create project hierarchy like:

```
.
├── Gemfile
└── tools
    └── hello_world.rb
```

with `Gemfile` below:

```ruby
source "https://rubygems.org"

gem "rbbcc"
```

Then run `bundle install`.

### With docker

_TBD_

## Hello world from Linux kernel!

Creating `tools/hello_world.rb` as:

```ruby
#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

text = <<CLANG
int kprobe__sys_clone(void *ctx)
{
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
CLANG

b = BCC.new(text: text)
printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "value")

b.trace_fields do |task, pid, cpu, flags, ts, msg|
  printf("%-18.9f %-16s %-6d %s", ts, task, pid, msg)
end
```

Then invoke this Ruby script. BCC requires to run as a priveleged user.

```console
$ sudo bundle exec ruby tools/hello_world.rb                                       
Found fnc: kprobe__sys_clone
Attach: p___x64_sys_clone
TIME(s)            COMM             PID    value
```

Open another terminal and hit commands, like `curl https://www.ruby-lang.org/`.

Then RbBCC process displays what kind of program invokes another program with message `Hello, World`.

```console
TIME(s)            COMM             PID    value
109979.625639000   bash             7591   Hello, World!
109979.632267000   curl             29098  Hello, World!
109981.467914000   bash             7591   Hello, World!
109981.474290000   curl             29100  Hello, World!
109984.913358000   bash             7591   Hello, World!
109984.921165000   curl             29102  Hello, World!
...
```

These lines are displayed by a kernel hook of `clone(2)(internally: sys_clone)` call. The bash command like `curl, grep, ping...` internally call `sys_clone` to fork new processes, and RbBCC traces these kernel calls with a very small cost.

Then, change the Ruby(and internal C) codes into this like:

```ruby
#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

text = <<CLANG
#include <uapi/linux/ptrace.h>

int printret(struct pt_regs *ctx) {
  char str[80] = {};
  u32 pid;
  if (!PT_REGS_RC(ctx))
      return 0;
  pid = bpf_get_current_pid_tgid();
  bpf_probe_read(&str, sizeof(str), (void *)PT_REGS_RC(ctx));
  bpf_trace_printk("[%d]input: %s\\n", pid, str);

  return 0;
};
CLANG

b = BCC.new(text: text)
b.attach_uretprobe(name: "/bin/bash", sym: "readline", fn_name: "printret")

printf("%-18s %-16s %s\n", "TIME(s)", "COMM", "value")
b.trace_fields do |task, pid, cpu, flags, ts, msg|
  printf("%-18.9f %-16s %s", ts, task, msg)
end
```

Run again:

```console
$ sudo bundle exec ruby tools/hello_world.rb                                       
Found fnc: printret
Attach: p__bin_bash_0xad900
TIME(s)            COMM             value
```

And open another "bash" terminal again. When you hit a command to this bash in any session, any input strings are snooped and shown in the tracing process. This is all of the trace result of return in `readline()` function from user program "bash". RbBCC can detect where and how it occurs.

```console
TIME(s)            COMM             value
1554.284390000     bash             [5457]input: curl localhost
1559.425699000     bash             [5457]input: ping 8.8.8.8
1565.805870000     bash             [5457]input: sudo cat /etc/passwd
...
```

----

For more use case and information. Please see [`examples`](../examples/) directory and (especially for C API) BCC's official document.

* [bcc Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
