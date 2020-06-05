#!/usr/bin/env ruby
#
# bashreadline  Print entered bash commands from all running shells.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: bashreadline [-s SHARED]
# This works by tracing the readline() function using a uretprobe (uprobes).
# When you failed to run the script directly with error:
# `Exception: could not determine address of symbol b'readline'`,
# you may need specify the location of libreadline.so library
# with `-s` option.
#
# Original bashreadline.py:
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
# And Ruby version follows.
#
# 28-Jan-2016    Brendan Gregg   Created bashreadline.py.
# 12-Feb-2016    Allan McAleavy migrated to BPF_PERF_OUTPUT
# 05-Jun-2020    Uchio Kondo     Ported bashreadline.rb

require 'rbbcc'
require 'optparse'
include RbBCC

args = {}
opts = OptionParser.new
opts.on("-s", "--shared=LIBREADLINE_PATH"){|v| args[:shared] = v }
opts.parse!(ARGV)

name = args[:shared] || "/bin/bash"

# load BPF program
bpf_text = <<BPF
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct str_t {
    u64 pid;
    char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data  = {};
    char comm[TASK_COMM_LEN] = {};
    u32 pid;
    if (!PT_REGS_RC(ctx))
        return 0;
    pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_probe_read(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));

    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0 ) {
        events.perf_submit(ctx,&data,sizeof(data));
    }


    return 0;
};
BPF

b = BCC.new(text: bpf_text)
b.attach_uretprobe(name: name, sym: "readline", fn_name: "printret")

# header
puts("%-9s %-6s %s" % ["TIME", "PID", "COMMAND"])

b["events"].open_perf_buffer do |cpu, data, size|
  event = b["events"].event(data)
  puts("%-9s %-6d %s" % [
         Time.now.strftime("%H:%M:%S"),
         event.pid,
         event.str
       ])
end

trap(:INT) { puts; exit }
loop do
  b.perf_buffer_poll
end
