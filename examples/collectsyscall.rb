#!/usr/bin/env ruby
#
# Example to use complecated structure in BPF Map key:
# This program collects and shows raw syscall usage summary.
#
# Usage:
#     bundle exec ruby examples/collectsyscall.rb
#
# Output example:
#     Collecting syscalls...
#     ^C
#     PID=1098(maybe: gmain) --->
#       inotify_add_watch      4    0.019 ms
#       poll                   1    0.000 ms
#
#     PID=1114(maybe: dbus-daemon) --->
#       stat                  12    0.021 ms
#       openat                 3    0.015 ms
#       getdents               2    0.013 ms
#       recvmsg                2    0.006 ms
#       sendmsg                1    0.008 ms
#       close                  1    0.002 ms
#       fstat                  1    0.002 ms
#       epoll_wait             1    0.000 ms
#
#     PID=1175(maybe: memcached) --->
#       epoll_wait             3 2012.455 ms
#
#     PID=1213(maybe: redis-server) --->
#       read                  64    0.736 ms
#       epoll_wait            32 3782.098 ms
#       openat                32    1.149 ms
#       getpid                32    0.074 ms
#       close                 32    0.045 ms
#     ....

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

# if no ausyscall(8) then shows number itself
# it is included in auditd package (e.g. Ubuntu)
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
