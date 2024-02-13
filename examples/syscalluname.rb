#!/usr/bin/env ruby
#
# syscalluname.rb Example of instrumenting a kernel tracepoint.
#
# Copyright 2024 Uchio Kondo
# Licensed under the Apache License, Version 2.0 (the "License")

require 'rbbcc'
include RbBCC

b = BCC.new(text: %[
#include <linux/utsname.h>

TRACEPOINT_PROBE(syscalls, sys_enter_newuname) {
    // args is from
    // /sys/kernel/debug/tracing/events/syscalls/sys_enter_newuname/format
    char release[16];
    bpf_probe_read_user_str(release, 16, args->name->release);
    // avoid broken data
    if (release[0] == '5' || release[0] == '6') {
        bpf_trace_printk("%s\\n", release);
    }
    return 0;
}
])

# header
printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "RELEASE")

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
