#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

pid = ARGV[0] || begin
  puts("USAGE: #{$0} PID")
  exit()
end
debug = !!ENV['DEBUG']

bpf_text = <<BPF
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    char comm[TASK_COMM_LEN];
    char klass[64];
    char path[256];
};
BPF_PERF_OUTPUT(events);

int do_trace_create_object(struct pt_regs *ctx) {
    struct data_t data = {};
    uint64_t addr, addr2;

    data.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_usdt_readarg_p(1, ctx, &data.klass, sizeof(data.klass));
    bpf_usdt_readarg_p(2, ctx, &data.path, sizeof(data.path));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
};
BPF

u = USDT.new(pid: pid.to_i)
u.enable_probe(probe: "object__create", fn_name: "do_trace_create_object")
if debug
  puts(u.get_text)
  puts(bpf_text)
end

# initialize BPF
b = BCC.new(text: bpf_text, usdt_contexts: [u])

puts("%-18s %-6s %-24s %s" % ["TIME(s)", "COMM", "KLASS", "PATH"])

# process event
start = 0
b["events"].open_perf_buffer do |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  puts(
    "%-18.9f %-6s %-24s %s" %
    [time_s, event.comm, event.klass, event.path]
  )
end

Signal.trap(:INT) { puts "\nDone."; exit }
loop do
  b.perf_buffer_poll()
end
