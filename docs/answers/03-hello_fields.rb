#!/usr/bin/env ruby
# Licensed under the Apache License, Version 2.0 (the "License")

require "rbbcc"
include RbBCC

# define BPF program
prog = <<BPF
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
BPF

# load BPF program
b = BCC.new(text: prog)
b.attach_kprobe(event: b.get_syscall_fnname("clone"), fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "MESSAGE"])

# format output
begin
  b.trace_fields do |task, pid, cpu, flags, ts, msg|
    print("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
  end
rescue Interrupt
  puts
  puts "Done"
rescue => e
  p e
  retry
end
