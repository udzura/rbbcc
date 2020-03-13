#!/usr/bin/env ruby
# Licensed under the Apache License, Version 2.0 (the "License")

require 'rbbcc'
include RbBCC

# load BPF program
b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
  dist.increment(bpf_log2l(req->__data_len / 1024));
  return 0;
}
BPF

# header
puts("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
begin
  loop { sleep 0.1 }
rescue Interrupt
  puts
end

# output
b["dist"].print_log2_hist("kbytes")
