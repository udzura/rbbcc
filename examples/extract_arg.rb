#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

code = <<CLANG
#include <uapi/linux/ptrace.h>
int kprobe__sys_execve(struct pt_regs *ctx) {
  if (!PT_REGS_PARM1(ctx))
    return 0;
  char str[80] = {};
  bpf_probe_read(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
  bpf_trace_printk("execve detected: %s\\n", &str);
  return 0;
}
CLANG

BCC.new(text: code).trace_print
