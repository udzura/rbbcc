require 'rbbcc'
include RbBCC

b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>

struct key_t {
  u32 pid;
  u64 syscall_nr;
};
struct leaf_t{
  u64 count;
  u64 elapsed_ns;
  u64 enter_ns;
  char comm[16];
};
BPF_HASH(store, struct key_t, struct leaf_t);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct key_t key = {0};
    struct leaf_t initial = {0, 0, (char *)NULL}, *val_;

    key.pid = bpf_get_current_pid_tgid();
    key.syscall_nr = args->id;

    val_ = store.lookup_or_try_init(&key, &initial);
    if (val_) {
      struct leaf_t val = *val_;
      val.count++;
      val.enter_ns = bpf_ktime_get_ns();
      bpf_get_current_comm(&val.comm, sizeof(val.comm));
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct key_t key = {0};
    struct leaf_t *val_;

    key.pid = bpf_get_current_pid_tgid();
    key.syscall_nr = args->id;

    val_ = store.lookup(&key);
    if (val_) {
      struct leaf_t val = *val_;
      u64 delta = bpf_ktime_get_ns() - val.enter_ns;
      val.enter_ns = 0;
      val.elapsed_ns += delta;
    }
    return 0;
}
BPF

begin
  sleep(99999999)
rescue Interrupt
  puts
end

store = b.get_table("store")
store.items.each do |k, v|
  require 'pry'; binding.pry
end
