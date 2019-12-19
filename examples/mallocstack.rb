#!/usr/bin/env ruby
#
# mallocstacks  Trace malloc() calls in a process and print the full
#               stack trace for all callsites.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# This script is a basic example of the new Linux 4.6+ BPF_STACK_TRACE
# table API.
#
# Copyright 2016 GitHub, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

require 'rbbcc'
include RbBCC

if ARGV.size == 0
  $stderr.puts("USAGE: mallocstacks PID")
  exit
end
pid = ARGV[0].to_i

# load BPF program
b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>

BPF_HASH(calls, int);
BPF_STACK_TRACE(stack_traces, 1024);

int alloc_enter(struct pt_regs *ctx, size_t size) {
    int key = stack_traces.get_stackid(ctx,
        BPF_F_USER_STACK|BPF_F_REUSE_STACKID);
    if (key < 0)
        return 0;

    // could also use `calls.increment(key, size);`
    u64 zero = 0, *val;
    val = calls.lookup_or_init(&key, &zero);
    if (val)
      (*val) += size;
    return 0;
};
CLANG

b.attach_uprobe(name: "c", sym: "malloc", fn_name: "alloc_enter", pid: pid)
puts("Attaching to malloc in pid %d, Ctrl+C to quit." % pid)

# sleep until Ctrl-C
loop do
  begin
    sleep 1
  rescue Interrupt
    break # pass
  end
end
calls = b.get_table("calls")
stack_traces = b.get_table("stack_traces")

calls.items.sort_by{|k, v| v.to_bcc_value }.reverse.each do |(k, v)|
  puts("%d bytes allocated at:" % v.to_bcc_value)
  stack_traces.walk(k) do |addr|
    require 'pry'; binding.pry
    puts("\t%s" % BCC.sym(addr, pid, show_offset: true))
  end
end
