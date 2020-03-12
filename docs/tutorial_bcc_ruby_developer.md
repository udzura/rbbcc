# RbBCC Ruby Developer Tutorial

* Original Python version is [at BCC's repo](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)
* This Ruby version of tutorial follows the license of BCC.

---

This tutorial is about developing bcc tools and programs using the Ruby interface, using [RbBCC](https://github.com/udzura/rbbcc/). In this time the oart of observability is implemented. Snippets are taken from various programs in [bcc](https://github.com/iovisor/bcc/tree/master/tools): see their files for licences. And we have implemented their Ruby versions and put them on [`answers/`](answers/).

Also see the bcc developer's [reference_guide.md](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bpf-c) for C interface.

There is also Python and lua interface for bcc. See original.

## Observability

This observability tutorial contains 17 lessons, and XX enumerated things to learn.

### Lesson 1. Hello World

Start by running [answers/01-hello-world.rb](answers/01-hello-world.rb), while running some commands (eg, "ls") in another session. It should print "Hello, World!" for new processes. If not, start by fixing bcc: see [BCC's INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) and [rbbcc getting started](getting_started.md).

```bash
## If you're running rbbcc in bundled environment, follow this command after `bundle exec'
# ruby answers/01-hello-world.rb
Found fnc: kprobe__sys_clone
Attach: p___x64_sys_clone
           <...>-17950 [000] .... 244107.900795: 0: Hello, World!
            bash-17950 [000] .... 244110.775263: 0: Hello, World!
            bash-17950 [000] .... 244114.080360: 0: Hello, World!
```

There are six things to learn from this:

1. ```text: '...'```: This defines a BPF program inline. The program is written in C.

1. ```kprobe__sys_clone()```: This is a short-cut for kernel dynamic tracing via kprobes. If the C function begins with ``kprobe__``, the rest is treated as a kernel function name to instrument, in this case, ```sys_clone()```.

1. ```void *ctx```: ctx has arguments, but since we aren't using them here, we'll just cast it to ```void *```.

1. ```bpf_trace_printk()```: A simple kernel facility for printf() to the common trace_pipe (/sys/kernel/debug/tracing/trace_pipe). This is ok for some quick examples, but has limitations: 3 args max, 1 %s only, and trace_pipe is globally shared, so concurrent programs will have clashing output. A better interface is via BPF_PERF_OUTPUT(), covered later.

1. ```return 0;```: Necessary formality (if you want to know why, see [bcc#139](https://github.com/iovisor/bcc/issues/139)).

1. ```Table#trace_print```: A bcc routine that reads trace_pipe and prints the output.

### Lesson 2. sys_sync()

Write a program that traces the sys_sync() kernel function. Print "sys_sync() called" when it runs. Test by running ```sync``` in another session while tracing. The hello_world.rb program has everything you need for this.

Improve it by printing "Tracing sys_sync()... Ctrl-C to end." when the program first starts. Hint: it's just Ruby and you can rescue `Interrupt` exception.

On of the answer exampkle is: [answers/02-sys_sync.rb](answers/02-sys_sync.rb)
