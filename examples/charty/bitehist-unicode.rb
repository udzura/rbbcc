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

require 'unicode_plot'
def log2hist_unicode(table)
  strip_leading_zero = true
  vals = Array.new($log2_index_max) { 0 }
  data = {}
  table.each_pair do |k, v|
    vals[k.to_bcc_value] = v.to_bcc_value
  end

  log2_dist_max = 64
  idx_max = -1
  val_max = 0

  vals.each_with_index do |v, i|
    idx_max = i if v > 0
    val_max = v if v > val_max
  end

  (1...(idx_max + 1)).each do |i|
    low = (1 << i) >> 1
    high = (1 << i)
    if (low == high)
      low -= 1
    end
    val = vals[i]

    if strip_leading_zero
      if val
        data["[#{low}, #{high})"] = val
        strip_leading_zero = false
      end
    else
      data["[#{low}, #{high})"] = val
    end
  end

  unless data.empty?
    puts UnicodePlot.barplot(ylabel: "kbytes", data: data, title: "log2 histogram", color: :magenta).render
  else
    puts "No sample found."
  end
end

log2hist_unicode b["dist"]

# puts
# puts "linear histogram"
# puts "~~~~~~~~~~~~~~~~"
# b["dist_linear"].print_linear_hist("kbytes")
