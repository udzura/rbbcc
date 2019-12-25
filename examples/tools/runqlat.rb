#!/usr/bin/env ruby
# @lint-avoid-python-3-compatibility-imports
#
# runqlat   Run queue (scheduler) latency as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: runqlat [-h] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends waiting on a run queue for a turn
# on-CPU, and shows this time as a histogram. This time should be small, but a
# task may need to wait its turn due to CPU load.
#
# This measures two types of run queue latency:
# 1. The time from a task being enqueued on a run queue to its context switch
#    and execution. This traces ttwu_do_wakeup(), wake_up_new_task() ->
#    finish_task_switch() with either raw tracepoints (if supported) or kprobes
#    and instruments the run queue latency after a voluntary context switch.
# 2. The time from when a task was involuntary context switched and still
#    in the runnable state, to when it next executed. This is instrumented
#    from finish_task_switch() alone.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

require 'rbbcc'
include RbBCC

bpf_text = <<TXT
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

typedef struct pid_key {
    u64 id;    // work around
    u64 slot;
} pid_key_t;

typedef struct pidns_key {
    u64 id;    // work around
    u64 slot;
} pidns_key_t;

BPF_HASH(start, u32);
STORAGE

struct rq;

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (FILTER || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}
TXT

bpf_text_raw_tp = <<TXT
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(FILTER || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = next->tgid;
    pid = next->pid;
    if (FILTER || pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    FACTOR

    // store as histogram
    STORE

    start.delete(&pid);
    return 0;
}
TXT

is_support_raw_tp = BCC.support_raw_tracepoint
if is_support_raw_tp
  bpf_text += bpf_text_raw_tp
else
  raise "BCC.support_raw_tracepoint is false; Unsupported kernel version: ${`uname -a`.chomp}"
end

bpf_text.gsub!('FILTER', '0')
bpf_text.gsub!('FACTOR', 'delta /= 1000;')
label = "usecs"
bpf_text.gsub!('STORAGE', 'BPF_HISTOGRAM(dist);')
bpf_text.gsub!('STORE',
        'dist.increment(bpf_log2l(delta));')
section = ""

b = BCC.new(text: bpf_text)

print("Tracing run queue latency... Hit Ctrl-C to end.")

# TODO: interval
loop do
  begin
    sleep 1
  rescue Interrupt
    break
  end
end

dist = b.get_table("dist")
dist.print_log2_hist(label, section, section_print_fn: :to_i)
# dist.clear()
exit
