#!/usr/bin/env ruby
#
# disksnoop.rb	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
# This is ported from original disksnoop.py
#
# Written as a basic example of tracing latency.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created disksnoop.py

require 'rbbcc'
include RbBCC

REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
  // stash start timestamp by request ptr
  u64 ts = bpf_ktime_get_ns();

  start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
  u64 *tsp, delta;

  tsp = start.lookup(&req);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    bpf_trace_printk("%d %x %d\\n", req->__data_len,
        req->cmd_flags, delta / 1000);
    start.delete(&req);
  }
}
CLANG

if BCC.get_kprobe_functions('blk_start_request')
  b.attach_kprobe(event: "blk_start_request", fn_name: "trace_start")
end
b.attach_kprobe(event: "blk_mq_start_request", fn_name: "trace_start")
b.attach_kprobe(event: "blk_account_io_completion", fn_name: "trace_completion")

# header
puts("%-18s %-2s %-7s %8s" % ["TIME(s)", "T", "BYTES", "LAT(ms)"])

# format output
loop do
  begin
    task, pid, cpu, flags, ts, msg = b.trace_fields
    bytes_s, bflags_s, us_s = msg.split

    if (bflags_s.to_i(16) & REQ_WRITE).nonzero?
      type_s = "W"
    elsif bytes_s == "0" # see blk_fill_rwbs() for logic
      type_s = "M"
    else
      type_s = "R"
    end
    ms = us_s.to_i.to_f / 1000

    puts("%-18.9f %-2s %-7s %8.2f" % [ts, type_s, bytes_s, ms])
  rescue Interrupt
    exit
  end
end
