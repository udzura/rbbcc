#!/usr/bin/env ruby
#
# urandomread-explicit.rb Example of instrumenting a kernel tracepoint.
#                         For Linux, uses BCC, BPF. Embedded C.
# Originally urandomread-explicit.py in BCC
#
# This is an older example of instrumenting a tracepoint, which defines
# the argument struct and makes an explicit call to attach_tracepoint().
# See urandomread for a newer version that uses TRACEPOINT_PROBE().
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support).
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# FIXME: random/urandom_read is removed from newer kernel!!

require 'rbbcc'
include RbBCC

# define BPF program
bpf_text = <<CLANG
#include <uapi/linux/ptrace.h>

struct urandom_read_args {
    // from /sys/kernel/debug/tracing/events/random/urandom_read/format
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};

int printarg(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
CLANG

# load BPF program
b = BCC.new(text: bpf_text)
b.attach_tracepoint(tp: "random:urandom_read", fn_name: "printarg")

# header
printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "GOTBITS")

# format output
loop do
  begin
    b.trace_fields do |task, pid, cpu, flags, ts, msg|
      puts("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
    end
  rescue Interrupt
    exit
  end
end
