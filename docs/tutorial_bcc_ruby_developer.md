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
