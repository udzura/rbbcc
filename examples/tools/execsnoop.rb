#!/usr/bin/env ruby
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
# originally from tools/execsnoop.py
#
# USAGE: execsnoop [-h] [-t] [-x] [-n NAME]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created execsnoop.py.

require 'optparse'
require 'ostruct'
require 'rbbcc'
include RbBCC

examples = <<USAGE
examples:
    ./execsnoop.rb           # trace all exec() syscalls
    ./execsnoop.rb -x        # include failed exec()s
    ./execsnoop.rb -t        # include timestamps
    ./execsnoop.rb -q        # add "quotemarks" around arguments
    ./execsnoop.rb -n main   # only print command lines containing "main"
    ./execsnoop.rb -l tpkg   # only print command where arguments contains "tpkg"
USAGE

args = OpenStruct.new
parser = OptionParser.new
parser.banner = <<BANNER
usage: execsnoop.rb [-h] [-t] [-x] [-q] [-n NAME] [-l LINE]
                    [--max-args MAX_ARGS]

Trace exec() syscalls

optional arguments:
BANNER
parser.on("-t", "--timestamp", "include timestamp on output") {|v| args.timestamp = v }
parser.on("-x", "--fails",     "include failed exec()s") {|v| args.fails = v }
parser.on("-q", "--quote",     "Add quotemarks (\") around arguments.") {|v| args.quote = v }
parser.on("-n", "--name NAME", "only print commands matching this name (regex), any arg") {|v| args.name = v }
parser.on("-l", "--line LINE", "only print commands where arg contains this line (regex)") {|v| args.line = v }
parser.on("--max-args MAX_ARGS", "maximum number of arguments parsed and displayed, defaults to 20") {|v| args.max_arges = v }
parser.on("--ebpf") {|v| opt.ebpf = v }

parser.on_tail("-h", "--help", "show this help message and exit") do
  puts parser
  puts
  puts examples
  exit
end

parser.parse!
args.max_arges ||= "20"

bpf_text = <<CLANG
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
CLANG

EVENT_ARG = 0
EVENT_RET = 1

def get_ppid(pid)
  0
end

bpf_text.sub!("MAXARG", args.max_args)
if args.ebpf
  puts(bpf_text)
  exit
end

b = BCC.new(text: bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event: execve_fnname, fn_name: "syscall__execve")
b.attach_kretprobe(event: execve_fnname, fn_name: "do_ret_sys_execve")

printf("%-8s", "TIME(s)") if args.timestamp
printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS")

start_ts = Time.now.to_f
argv = []

b["events"].open_perf_buffer do |cpu, data, size|
  event = b["events"].event(data)
  skip = false
  if event.type == EVENT_ARG
    argv[event.pid] ||= []
    argv[event.pid] << event.argv
  elsif event.type == EVENT_RET
    skip = true if event.retval != 0 && !args.fails
    skip = true if args.name && /#{args.name}/ !~ event.comm
    skip = true if args.line && /#{args.line}/ !~ argv[event.pid].join(' ')
    if args.quote
      argv[event.pid] = argv[event.pid].map{|arg| '"' + arg.gsub(/\"/, '\\"') + '"' }
    end

    unless skip
      ppid_ = event.ppid > 0 ? event.ppid : get_ppid(event.pid)
      ppid = ppid_ > 0 ? ppid_.to_s : "?"
      argv_text = argv[event.pid].join(' ').gsub(/\n/, '\\n') rescue ""
      printf("%-8.3f", (Time.now.to_f - start_ts)) if args.timestamp
      printf("%-16s %-6d %-6s %3d %s\n",
             event.comm, event.pid, ppid, event.retval, argv_text)
    end

    argv[event.pid] = nil
  end
end

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    exit
  end
end
