#!/usr/bin/env ruby
#
# This is a Hello World example that formats output as fields.

require 'rbbcc'
include RbBCC

# define BPF program
prog = <<CLANG
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
CLANG

# load BPF program
b = BCC.new(text: prog)
b.attach_kprobe(event: b.get_syscall_fnname("clone"), fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "MESSAGE"])

# format output
loop do
  begin
    b.trace_fields do |task, pid, cpu, flags, ts, msg|
      puts("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
    end
  rescue Interrupt
    exit
  end
end
