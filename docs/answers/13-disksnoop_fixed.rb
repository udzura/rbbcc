#!/usr/bin/env ruby
#
# disksnoop_fixed.rb	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
# This is ported from original disksnoop.py
#
# Written as a basic example of tracing latency.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created disksnoop.py

=begin
name: block_rq_issue
ID: 1093
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:dev_t dev;        offset:8;       size:4; signed:0;
        field:sector_t sector;  offset:16;      size:8; signed:0;
        field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
        field:unsigned int bytes;       offset:28;      size:4; signed:0;
        field:char rwbs[8];     offset:32;      size:8; signed:1;
        field:char comm[16];    offset:40;      size:16;        signed:1;
        field:__data_loc char[] cmd;    offset:56;      size:4; signed:1;

print fmt: "%d,%d %s %u (%s) %llu + %u [%s]", ((unsigned int) ((REC->dev) >> 20)), ((unsigned int) ((REC->dev) & ((1U << 20) - 1))), REC->rwbs, REC->bytes, __get_str(cmd), (unsigned long long)REC->sector, REC->nr_sector, REC->comm

name: block_rq_complete
ID: 1095
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:dev_t dev;        offset:8;       size:4; signed:0;
        field:sector_t sector;  offset:16;      size:8; signed:0;
        field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
        field:int error;        offset:28;      size:4; signed:1;
        field:char rwbs[8];     offset:32;      size:8; signed:1;
        field:__data_loc char[] cmd;    offset:40;      size:4; signed:1;

print fmt: "%d,%d %s (%s) %llu + %u [%d]", ((unsigned int) ((REC->dev) >> 20)), ((unsigned int) ((REC->dev) & ((1U << 20) - 1))), REC->rwbs, __get_str(cmd), (unsigned long long)REC->sector, REC->nr_sector, REC->error

in kernel 5.0.
This implementation shows the count of sector.
=end

require 'rbbcc'
include RbBCC

# load BPF program
b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, u32);

TRACEPOINT_PROBE(block, block_rq_issue) {
  // stash start timestamp by request ptr
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start.update(&tid, &ts);
  return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
  u64 *tsp, delta;
  u32 tid = bpf_get_current_pid_tgid();

  tsp = start.lookup(&tid);
  if (tsp != 0) {
    char dst[8];
    int i;
    delta = bpf_ktime_get_ns() - *tsp;
    if (bpf_probe_read_str(dst, sizeof(dst), args->rwbs) < 0) {
      dst[0] = '?';
      for(i = 1; i < sizeof(dst); ++i)
        dst[i] = 0;
    }
    bpf_trace_printk("%d %s %d\\n", args->nr_sector,
        dst, delta / 1000);
    start.delete(&tid);
  }
  return 0;
}
CLANG

# header
puts("%-18s %-8s %-7s %8s" % ["TIME(s)", "RWBS", "SECTORS", "LAT(ms)"])

# format output
loop do
  begin
    task, pid, cpu, flags, ts, msg = b.trace_fields
    sector_s, rwbs, us_s = msg.split
    ms = us_s.to_i.to_f / 1000

    puts("%-18.9f %-8s %-7s %8.2f" % [ts, rwbs, sector_s, ms])
  rescue Interrupt
    exit
  end
end
