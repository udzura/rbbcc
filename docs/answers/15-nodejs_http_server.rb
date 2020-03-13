require 'rbbcc'
include RbBCC

if ARGV.size != 1
  print("USAGE: #{$0} PID")
  exit()
end
pid = ARGV[0]
debug = !!ENV['DEBUG']

# load BPF program
bpf_text = <<BPF
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={0};
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
BPF

# enable USDT probe from given PID
u = USDT.new(pid: pid.to_i)
u.enable_probe(probe: "http__server__request", fn_name: "do_trace")
if debug
  puts(u.get_text)
  puts(bpf_text)
end

# initialize BPF
b = BCC.new(text: bpf_text, usdt_contexts: [u])

puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "ARGS"])
loop do
  begin
    b.trace_fields do |task, pid, cpu, flags, ts, msg|
      puts("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
    end
  rescue Interrupt
    exit
  end
end
