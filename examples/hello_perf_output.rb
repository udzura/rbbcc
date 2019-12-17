#!/usr/bin/env ruby
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.
# Ported from hello_perf_output.py

require 'rbbcc'
include RbBCC

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BCC.new(text: prog)
# b.get_syscall_fnname("clone") => "__x64_sys_clone"
b.attach_kprobe(event: "__x64_sys_clone", fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "MESSAGE"])

# process event
start = 0
print_event = lambda { |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  puts("%-18.9f %-16s %-6d %s" % [time_s, event.comm.pack("c*").strip, event.pid,
                                  "Hello, perf_output!"])
}

# loop with callback to print_event
b["events"].open_perf_buffer(&print_event)

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    exit()
  end
end
