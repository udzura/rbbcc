#!/usr/bin/env ruby
#
# urandomread.rb Example of instrumenting a kernel tracepoint.
#                For Linux, uses BCC, BPF. Embedded C.
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support).
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5
#
# Original urandomread.py Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
# Ruby version follows.

require 'rbbcc'
include RbBCC

b = BCC.new(text: <<BPF)
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
BPF

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "GOTBITS"])

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
