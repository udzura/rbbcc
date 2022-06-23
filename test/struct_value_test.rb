require 'minitest/autorun'
require 'rbbcc'
require 'timeout'

class StructValueTest < Minitest::Test
  include RbBCC
  def setup
    code = <<~CLANG
struct key_t {
  u32 pid;
  u64 value1;
};
struct leaf_t{
  u64 value2;
  char str[32];
};
BPF_HASH(store, struct key_t, struct leaf_t);

int trace_sync(void *ctx)
{
  char src[] = "TestString001";
  struct key_t key = {0};
  struct leaf_t *val_, init = {0};

  key.pid = bpf_get_current_pid_tgid();
  key.value1 = 1234567;

  val_ = store.lookup_or_try_init(&key, &init);
  if (val_) {
    struct leaf_t val = *val_;
    val.value2 = 7654321;
    bpf_probe_read(val.str, sizeof(src), (void *)src);
    store.update(&key, &val);
  }
  return 0;
}
    CLANG
    @module = BCC.new(text: code)
    @module.attach_kprobe(
      event: @module.get_syscall_fnname("sync"),
      fn_name: "trace_sync"
    )
    @pid = nil
  end

  def test_get_map_value
    @pid = fork {
      sleep 0.05
      exec "sync"
    }

    got = {}
    Timeout.timeout(1) do
      while got.empty?
        got = @module['store'].items rescue {}
      end
    end

    k, v = *got.first
    assert_equal(@pid, k.pid)
    assert_equal(1234567, k.value1)
    assert_equal(7654321, v.value2)
    assert_equal("TestString001", v.str)
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
