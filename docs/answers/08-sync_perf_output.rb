#!/usr/bin/env ruby
# Licensed under the Apache License, Version 2.0 (the "License")

require "rbbcc"
include RbBCC

# load BPF program
b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u64 ts;
    u64 delta;
};
BPF_PERF_OUTPUT(events);
BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != 0) {
        struct data_t data = {};
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            data.pid = bpf_get_current_pid_tgid();
            data.ts = bpf_ktime_get_ns();
            data.delta = delta;
            events.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
BPF

b.attach_kprobe(event: b.get_syscall_fnname("sync"), fn_name: "do_trace")
puts("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
b["events"].open_perf_buffer do |_, data, _|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1_000_000_000
  puts("At time %.2f s: multiple syncs detected, last %s ms ago" % [time_s, event.delta / 1_000_000])
end

loop do
  b.perf_buffer_poll()
end
