#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

code = <<CLANG
#include <uapi/linux/ptrace.h>
#define ARGSIZE 128

// must be syscall__${the_name} ?
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
  char buf[ARGSIZE] = {};
  bpf_probe_read(buf, sizeof(buf), (void *)filename);
  bpf_trace_printk("execve: %s\\n", &buf);

  return 0;
}
CLANG

b = BCC.new(text: code)
b.attach_kprobe(event: b.get_syscall_fnname("execve"), fn_name: "syscall__execve")
b.trace_print
