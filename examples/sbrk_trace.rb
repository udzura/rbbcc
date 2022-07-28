#!/usr/bin/env ruby
# Trace example for libc's USDT:
# - memory_sbrk_more
# - memory_sbrk_less
# - memory_mallopt_free_dyn_thresholds
# Description is here: https://www.gnu.org/software/libc/manual/html_node/Memory-Allocation-Probes.html
#
# Example output:
# bundle exec ruby examples/sbrk_trace.rb -c ruby
# !! Trace start.
# [       0.000000000] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x55f34b979000 size=135168
# [       0.036549804] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd9760000 size=135168
# [       0.036804183] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd9781000 size=143360
# [       0.036855378] pid=32756 comm=ruby probe=memory_sbrk_less addr=0x557fd97a0000 size=16384
# [       0.036931376] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd97a0000 size=147456
# [       0.036940382] pid=32756 comm=ruby probe=memory_sbrk_less addr=0x557fd97c0000 size=16384
# [       0.037022971] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd97c0000 size=151552
# [       0.038602464] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd97e5000 size=204800
# [       0.039398297] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd9817000 size=135168
# [       0.039909594] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd9838000 size=135168
# [       0.040536005] pid=32756 comm=ruby probe=memory_sbrk_more addr=0x557fd9859000 size=163840
# ...

require 'rbbcc'
include RbBCC

def usage
  puts("USAGE: #{$0} [-p PID|-c COMM]")
  exit()
end

def find_libc_location
  if File.exist?('/lib/x86_64-linux-gnu/libc.so.6')
    '/lib/x86_64-linux-gnu/libc.so.6'
  else
    `find /lib/ -name 'libc.so*' | tail -1`.chomp
  end
end

usage if ARGV.size != 0 && ARGV.size != 2

pid = comm = nil
path = find_libc_location
case ARGV[0]
when '-p', '--pid'
  pid = ARGV[1].to_i
when '-c', '--comm'
  comm = ARGV[1]
when nil
  # nop
else
  usage
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

static inline bool streq(uintptr_t str) {
    char needle[] = "{{NEEDLE}}";
    char haystack[sizeof(needle)];
    bpf_probe_read(&haystack, sizeof(haystack), (void *)str);
    for (int i = 0; i < sizeof(needle) - 1; ++i) {
        if (needle[i] != haystack[i]) {
            return false;
        }
    }
    return true;
}

#define PROBE_TYPE_more 1
#define PROBE_TYPE_less 2
#define PROBE_TYPE_free 3

{{FUNC_MORE}}

{{FUNC_LESS}}

int trace_memory_free(struct pt_regs *ctx) {
    struct data_t data = {};
    long buf;

    data.type = PROBE_TYPE_free;
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    {{NEEDLE_START}}
    bpf_usdt_readarg(1, ctx, &buf);
    data.adjusted_mmap = buf;

    bpf_usdt_readarg(2, ctx, &buf);
    data.trim_thresholds = buf;

    events.perf_submit(ctx, &data, sizeof(data));
    {{NEEDLE_END}}

    return 0;
};

BPF

trace_fun_sbrk = <<FUNC
int trace_memory_sbrk_{{TYPE}}(struct pt_regs *ctx) {
    struct data_t data = {};
    long buf;

    data.type = PROBE_TYPE_{{TYPE}};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    {{NEEDLE_START}}
    bpf_usdt_readarg(1, ctx, &buf);
    data.addr = buf;

    bpf_usdt_readarg(2, ctx, &buf);
    data.sbrk_size = buf;

    events.perf_submit(ctx, &data, sizeof(data));
    {{NEEDLE_END}}

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

if comm
  bpf_text.sub!('{{NEEDLE}}', comm)
  bpf_text.gsub!('{{NEEDLE_START}}', "if(streq((uintptr_t)data.comm)) {")
  bpf_text.gsub!('{{NEEDLE_END}}', "}")
else
  bpf_text.sub!('{{NEEDLE}}', "")
  bpf_text.gsub!('{{NEEDLE_START}}', "")
  bpf_text.gsub!('{{NEEDLE_END}}', "")
end

u = USDT.new(pid: pid, path: path)
u.enable_probe(probe: "memory_sbrk_more", fn_name: "trace_memory_sbrk_more")
u.enable_probe(probe: "memory_sbrk_less", fn_name: "trace_memory_sbrk_less")
if pid
  # FIXME: Only available when PID is specified
  # otherwise got an error:
  #     bpf: Failed to load program: Invalid argument
  #     last insn is not an exit or jmp
  # It seems libbcc won't generate proper readarg helper
  u.enable_probe(probe: "memory_mallopt_free_dyn_thresholds", fn_name: "trace_memory_free")
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
  if [PROBE_TYPE_more, PROBE_TYPE_less].include?(event.type)
    puts(
      "[%18.9f] pid=%d comm=%s probe=%s addr=%#x size=%d" %
      [time_s, event.pid, event.comm, PROBE_MAP[event.type], event.addr, event.sbrk_size]
    )
  else
    puts(
      "[%18.9f] pid=%d comm=%s probe=%s adjusted_mmap=%d trim_thresholds=%d" %
      [time_s, event.pid, event.comm, PROBE_MAP[event.type], event.adjusted_mmap, event.trim_thresholds]
    )
  end
end

Signal.trap(:INT) { puts "\n!! Done."; exit }
loop do
  b.perf_buffer_poll()
end
