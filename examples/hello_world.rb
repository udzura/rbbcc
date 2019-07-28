#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

BCC.new(text: 'int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print
