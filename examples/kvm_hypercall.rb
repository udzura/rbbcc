#!/usr/bin/python
#
# kvm_hypercall.rb - TODO: it is still not tested
# See original kvm_hypercall.py and txt
#
# Demonstrates stateful kvm_entry and kvm_exit recording along with the
# associated hypercall when exit_reason is VMCALL. See kvm_hypercall.txt
# for usage
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2017 ShiftLeft Inc.
#
# Author(s):
#   Suchakrapani Sharma <suchakra@shiftleft.io>

require 'rbbcc'
include RbBCC

# load BPF program
b = BCC.new(text: <<CLANG)
#define EXIT_REASON 18
BPF_HASH(start, u8, u8);

TRACEPOINT_PROBE(kvm, kvm_exit) {
    u8 e = EXIT_REASON;
    u8 one = 1;
    if (args->exit_reason == EXIT_REASON) {
        bpf_trace_printk("KVM_EXIT exit_reason : %d\\n", args->exit_reason);
        start.update(&e, &one);
    }
    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_entry) {
    u8 e = EXIT_REASON;
    u8 zero = 0;
    u8 *s = start.lookup(&e);
    if (s != NULL && *s == 1) {
        bpf_trace_printk("KVM_ENTRY vcpu_id : %u\\n", args->vcpu_id);
        start.update(&e, &zero);
    }
    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_hypercall) {
    u8 e = EXIT_REASON;
    u8 zero = 0;
    u8 *s = start.lookup(&e);
    if (s != NULL && *s == 1) {
        bpf_trace_printk("HYPERCALL nr : %d\\n", args->nr);
    }
    return 0;
};
CLANG

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "EVENT"])

# format output
loop do
  begin
    b.trace_fields do |task, pid, cpu, flags, ts, msg|
      puts("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
    end
  rescue Interrupt
    exit
  end
end
