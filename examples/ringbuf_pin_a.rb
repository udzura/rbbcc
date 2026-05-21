#!/usr/bin/env ruby
require 'rbbcc'
include RbBCC

PIN_PATH = "/sys/fs/bpf/pinned_ringbuf"

if File.exist?(PIN_PATH)
  puts "Removing old pinned map at #{PIN_PATH}..."
  File.unlink(PIN_PATH)
end

bpf_text = <<~CLANG
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 4);

int trace_uname(struct pt_regs *ctx) {
    struct data_t *data = events.ringbuf_reserve(sizeof(struct data_t));
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    events.ringbuf_submit(data, 0);
    return 0;
}
CLANG

puts "Process A (Ruby): Loading BPF and attaching tracepoint..."
b = BCC.new(text: bpf_text)
b.attach_tracepoint(tp: "syscalls:sys_enter_newuname", fn_name: "trace_uname")

puts "Process A (Ruby): Pinning ringbuf map to #{PIN_PATH}..."
b["events"].pin!(PIN_PATH)

puts "\n[Process A Active] Kept alive to feed events. Press Ctrl+C to stop."
begin
  loop do
    sleep 1
  end
ensure
  if File.exist?(PIN_PATH)
    puts "\nUnpinning map..."
    File.unlink(PIN_PATH)
  end
end
