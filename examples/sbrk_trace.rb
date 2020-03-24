#!/usr/bin/env ruby
# Trace example for libc's USDT:
# - memory_sbrk_more
# - memory_sbrk_less
# - memory_mallopt_free_dyn_thresholds
# Description is here: https://www.gnu.org/software/libc/manual/html_node/Memory-Allocation-Probes.html
#

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
    u32 type;
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 addr;
    u32 sbrk_size;
    u32 adjusted_mmap;
    u32 trim_thresholds;
};
BPF_PERF_OUTPUT(events);

#define PROBE_TYPE_more 1
#define PROBE_TYPE_less 2
#define PROBE_TYPE_free 3

{{FUNC_MORE}}

{{FUNC_LESS}}

BPF

trace_fun_sbrk = <<FUNC
int trace_memory_sbrk_{{TYPE}}(struct pt_regs *ctx, void *arg1, u32 arg2) {
    struct data_t data = {};
    long buf;

    data.type = PROBE_TYPE_{{TYPE}};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_usdt_readarg(1, ctx, &buf);
    data.addr = buf1;

    bpf_usdt_readarg(2, ctx, &buf);
    data.sbrk_size = buf1;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
};
FUNC

PROBE_TYPE_more = 1
PROBE_TYPE_less = 2
PROBE_TYPE_free = 3
PROBE_MAP = {
  PROBE_TYPE_more => 'memory_sbrk_more',
  PROBE_TYPE_less => 'memory_sbrk_less',
  PROBE_TYPE_free => 'memory_mallopt_free_dyn_thresholds'
}

bpf_text.sub!('{{FUNC_MORE}}', trace_fun_sbrk.gsub('{{TYPE}}', 'more'))
bpf_text.sub!('{{FUNC_LESS}}', trace_fun_sbrk.gsub('{{TYPE}}', 'less'))

u = USDT.new(pid: pid.to_i)
u.enable_probe(probe: "memory_sbrk_more", fn_name: "trace_memory_sbrk_more")
u.enable_probe(probe: "memory_sbrk_less", fn_name: "trace_memory_sbrk_less")
if debug
  puts(u1.get_text)
end

# initialize BPF
b = BCC.new(text: bpf_text, usdt_contexts: [u])

puts "!! Trace start."
# process event
start = 0
b["events"].open_perf_buffer do |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  puts(
    "[%-18.9f] pid=%d comm=%s probe=%s addr=%#x size=%d" %
    [time_s, event.pid, event.comm, PROBE_MAP[event.type], event.addr, event.sbrk_size]
  )
end

Signal.trap(:INT) { puts "\n!! Done."; exit }
loop do
  b.perf_buffer_poll()
end
