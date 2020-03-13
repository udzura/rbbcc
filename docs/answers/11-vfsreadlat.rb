#!/usr/bin/env ruby
#
# Original: from vfsreadlat.py
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
# Ruby version follows.
#
# vfsreadlat.rb		VFS read latency distribution.
#			For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of a function latency distribution histogram.
#
# USAGE: vfsreadlat.rb [interval [count]]
#
# The default interval is 5 seconds. A Ctrl-C will print the partially
# gathered histogram then exit.

require "rbbcc"
include RbBCC

def usage
  puts("USAGE: %s [interval [count]]" % $0)
  exit
end

# arguments
interval = 5
count = -1
if ARGV.size > 0
  begin
    interval = ARGV[0].to_i
    raise if interval == 0
    count = ARGV[1].to_i if ARGV[1]
  rescue	=> e # also catches -h, --help
    usage()
  end
end

# load BPF program
b = BCC.new(src_file: "11-vfsreadlat.c")
b.attach_kprobe(event: "vfs_read", fn_name: "do_entry")
b.attach_kretprobe(event: "vfs_read", fn_name: "do_return")

# header
print("Tracing... Hit Ctrl-C to end.")

# output
cycle = 0
do_exit = false
loop do
  if count > 0
    cycle += 1
    exit if cycle > count
  end

  begin
    sleep(interval)
  rescue Interrupt
    do_exit = true
  end

  puts
  b["dist"].print_log2_hist("usecs")
  b["dist"].clear
  exit if do_exit
end
