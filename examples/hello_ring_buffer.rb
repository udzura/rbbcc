#!/usr/bin/env ruby
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.
# Ported from hello_perf_output.py

require 'rbbcc'
include RbBCC

# define BPF program
prog = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    buffer.ringbuf_output(&data, sizeof(data), 0);

    return 0;
}
"""

# load BPF program
b = BCC.new(text: prog)
b.attach_kprobe(event: b.get_syscall_fnname("clone"), fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "MESSAGE"])

# process event
start = 0
print_event = lambda { |ctx, data, size|
  event = b["buffer"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  # event.comm.pack("c*").sprit
  puts("%-18.9f %-16s %-6d %s" % [time_s, event.comm, event.pid,
                                  "Hello, ringbuf!"])
}

# loop with callback to print_event
b["buffer"].open_ring_buffer(&print_event)

loop do
  begin
    b.ring_buffer_poll()
    sleep(0.5)
  rescue Interrupt
    exit()
  end
end
