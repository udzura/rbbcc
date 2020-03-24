#!/usr/bin/env ruby
# To run this example, please build the target ruby with an `--enable-dtrace` option in advance.
# To build via rbenv, sample command is:
#     $ RUBY_CONFIGURE_OPTS='--enable-dtrace' rbenv install 2.7.0
#
# Example autput:
#     # bundle exec ruby examples/ruby_usdt.rb $(pidof irb)
#     TIME(s)            COMM   KLASS                    PATH
#     0.000000000        irb    Struct::Key              /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline.rb
#     0.000055206        irb    Array                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.000088588        irb    Ripper::Lexer            /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000117740        irb    Ripper::Lexer::Elem      /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000126697        irb    Ripper::Lexer::State     /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000213388        irb    Array                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.000225678        irb    Ripper::Lexer            /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000243638        irb    Array                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.000254680        irb    Range                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/irb/ruby-lex.rb
#     0.000264707        irb    Ripper::Lexer            /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000275579        irb    Ripper::Lexer::Elem      /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000282438        irb    Ripper::Lexer::State     /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.000326136        irb    String                   /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/irb.rb
#     0.001353621        irb    Array                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.001385320        irb    IRB::Color::SymbolState  /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/irb/color.rb
#     0.001397043        irb    Ripper::Lexer            /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/irb/color.rb
#     0.001416420        irb    Ripper::Lexer::Elem      /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.001423861        irb    Ripper::Lexer::State     /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.001462010        irb    Ripper::Lexer::State     /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.001478995        irb    Array                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.001487499        irb    Range                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/irb/ruby-lex.rb
#     0.001496666        irb    Ripper::Lexer            /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.001508224        irb    Ripper::Lexer::Elem      /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.001515143        irb    Ripper::Lexer::State     /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/ripper/lexer.rb
#     0.001556170        irb    String                   /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/irb.rb
#     0.001726273        irb    String                   /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.001946948        irb    Array                    /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline/line_editor.rb
#     0.001956585        irb    String                   /root/.rbenv/versions/2.7.0/lib/ruby/2.7.0/reline.rb

require 'rbbcc'
include RbBCC

pid = ARGV[0] || begin
  puts("USAGE: #{$0} PID")
  exit()
end
debug = !!ENV['DEBUG']

bpf_text = <<BPF
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    char comm[TASK_COMM_LEN];
    char klass[64];
    char path[256];
};
BPF_PERF_OUTPUT(events);

int do_trace_create_object(struct pt_regs *ctx) {
    struct data_t data = {};
    uint64_t addr, addr2;

    data.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_usdt_readarg_p(1, ctx, &data.klass, sizeof(data.klass));
    bpf_usdt_readarg_p(2, ctx, &data.path, sizeof(data.path));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
};
BPF

u = USDT.new(pid: pid.to_i)
u.enable_probe(probe: "object__create", fn_name: "do_trace_create_object")
if debug
  puts(u.get_text)
  puts(bpf_text)
end

# initialize BPF
b = BCC.new(text: bpf_text, usdt_contexts: [u])

puts("%-18s %-6s %-24s %s" % ["TIME(s)", "COMM", "KLASS", "PATH"])

# process event
start = 0
b["events"].open_perf_buffer do |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  puts(
    "%-18.9f %-6s %-24s %s" %
    [time_s, event.comm, event.klass, event.path]
  )
end

Signal.trap(:INT) { puts "\nDone."; exit }
loop do
  b.perf_buffer_poll()
end
