require 'minitest/autorun'
#require "minitest/reporters"
#Minitest::Reporters.use! [Minitest::Reporters::SpecReporter.new]

require 'rbbcc'

class BCCHelloTest < Minitest::Test
  include RbBCC
  def setup
    code = <<~CLANG
      int kprobe__sys_clone(void *ctx)
      {
        bpf_trace_printk("Hello, World!\\n");
        return 0;
      }
    CLANG
    @module = BCC.new(text: code)
  end

  def test_clone
    @pid = fork {
      sleep 0.05
      system "bash -c 'echo Test'"
    }

    comm, pid, cpu, flags, ts, msg = @module.trace_fields
    assert_equal("ruby", comm)
    assert_match(/\A\d+\z/, pid)
    assert_match(/\A\d+\.\d+\z/, ts)
    assert_equal("Hello, World!\n", msg)
  end

  def teardown
    if @pid
      Process.kill :TERM, @pid
      Process.waitpid @pid
    end
  rescue => e
    warn e.inspect, "Skip teardown"
  end
end
