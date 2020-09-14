require 'rbbcc'
include RbBCC

# load BPF program
b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
BPF
b.attach_uprobe(name: "c", sym: "strlen", fn_name: "count")

# header
print("Tracing strlen()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
begin
  sleep(99999999)
rescue Interrupt
  puts
end

# print output
puts("%10s %s" % ["COUNT", "STRING"])
counts = b.get_table("counts")
counts.items.sort_by{|k, v| v.to_bcc_value }.each do |k, v|
  puts("%10d %s" % [v.to_bcc_value, k.to_bcc_value])
end
