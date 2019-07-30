require 'rbbcc'
include RbBCC

pid = ARGV[0]

bpf_text = <<CLANG
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    long buf, tgt;
    bpf_usdt_readarg(1, ctx, &buf);
    bpf_probe_read(&tgt, sizeof(tgt), (void *)&buf);
    bpf_trace_printk("%ld\\n", tgt);
    return 0;
};
CLANG

u = USDT.new(pid: pid.to_i)
u.enable_probe(probe: "mruby", fn_name: "do_trace")

b = BCC.new(text: bpf_text, usdt_contexts: [u])

printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "mruby-probe")

b.trace_fields do |task, pid, cpu, flags, ts, msg|
  printf("%-18.9f %-16s %-6d %s", ts, task, pid, msg)
end
