#!/usr/bin/env ruby
# Licensed under the Apache License, Version 2.0 (the "License")

require 'rbbcc'
include RbBCC

b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, struct request *);
BPF_HISTOGRAM(dist);

// note this program mixes R/W
// For next step, handle req->cmd_flags and prepare hist hash per op.

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
    dist.increment(bpf_log2l(delta / 1000)); // us
    start.delete(&req);
  }
}
BPF

b.attach_kprobe(event: "blk_start_request", fn_name: "trace_start") if BCC.get_kprobe_functions('blk_start_request')
b.attach_kprobe(event: "blk_mq_start_request", fn_name: "trace_start")
b.attach_kprobe(event: "blk_account_io_completion", fn_name: "trace_completion")

# header
puts("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
begin
  loop { sleep 0.1 }
rescue Interrupt
  puts
end

# output
b["dist"].print_log2_hist("usec")
