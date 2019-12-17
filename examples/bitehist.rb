#!/usr/bin/env ruby
#
# bitehist.rb, ported from bitehist.py. See license on that file
#
# Written as a basic example of using histograms to show a distribution.
#
# A Ctrl-C will print the gathered histogram then exit.
#

require 'rbbcc'
include RbBCC

b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(dist_linear);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
  dist.increment(bpf_log2l(req->__data_len / 1024));
  dist_linear.increment(req->__data_len / 1024);
  return 0;
}
CLANG

puts "Tracing... Hit Ctrl-C to end."

loop do
  begin
    sleep 0.1
  rescue Interrupt
    puts
    break
  end
end

puts "log2 histogram"
puts "~~~~~~~~~~~~~~"
b["dist"].print_log2_hist("kbytes")

puts
puts "linear histogram"
puts "~~~~~~~~~~~~~~~~"
b["dist_linear"].print_linear_hist("kbytes")
