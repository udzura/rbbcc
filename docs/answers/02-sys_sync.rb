#!/usr/bin/env ruby
# Licensed under the Apache License, Version 2.0 (the "License")

require "rbbcc"
include RbBCC

puts "Tracing sys_sync()... Ctrl-C to end."
begin
  BCC.new(text: <<~BPF).trace_print
    int kprobe__sys_sync(void *ctx) {
      bpf_trace_printk("sys_sync() called\\n");
      return 0;
    }
  BPF
rescue Interrupt
  puts
  puts "Done"
end
