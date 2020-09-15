require 'rbbcc'
include RbBCC

$pid = nil

if ARGV.size == 2 &&
   ARGV[0] == '-p'
  $pid = ARGV[1].to_i
elsif ARGV[0] == '-h' ||
      ARGV[0] == '--help'
  $stderr.puts "Usage: #{$0} [-p PID]"
  exit 1
end

SYSCALL_MAP = `ausyscall --dump`
                .lines
                .map{|l| l.chomp.split }
                .each_with_object(Hash.new) {|(k, v), ha| ha[k.to_i] = v }

def to_name(nr)
  SYSCALL_MAP[nr] || nr.to_s
end

prog = <<BPF
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
    struct leaf_t initial = {0}, *val_;

    key.pid = bpf_get_current_pid_tgid();
    key.syscall_nr = args->id;

    DO_FILTER_BY_PID

    val_ = store.lookup_or_try_init(&key, &initial);
    if (val_) {
      struct leaf_t val = *val_;
      val.count++;
      val.enter_ns = bpf_ktime_get_ns();
      bpf_get_current_comm(&val.comm, sizeof(val.comm));
      store.update(&key, &val);
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
      store.update(&key, &val);
    }
    return 0;
}
BPF

if $pid
  prog.sub!('DO_FILTER_BY_PID', <<~FILTER)
    if (key.pid != #{$pid}) return 0;
  FILTER
else
  prog.sub!('DO_FILTER_BY_PID', '')
end

b = BCC.new(text: prog)

puts "Collecting syscalls..."
begin
  sleep(99999999)
rescue Interrupt
  puts
end

info_by_pids = {}
comms = {}
store = b.get_table("store")
store.items.each do |k, v|
  # require 'pry'; binding.pry
  info_by_pids[k.pid] ||= {}
  info_by_pids[k.pid][k.syscall_nr] = {
    name: to_name(k.syscall_nr),
    count: v.count,
    elapsed_ms: v.elapsed_ns / 1000000.0
  }
  comms[k.pid] ||= v.comm
end

pids = info_by_pids.keys.sort
pids.each do |pid|
  puts "PID=#{pid}(maybe: #{comms[pid]}) --->"
  i = info_by_pids[pid]
  i.to_a.sort_by {|k, v| [-v[:count], -v[:elapsed_ms]] }.each do |nr, record|
    puts "\t%<name>-20s %<count>3d %<elapsed_ms>8.3f ms" % record
  end
  puts
end
