require 'minitest/autorun'
require 'rbbcc'

class TableLeafSizeTest < Minitest::Test
  include RbBCC

  def setup
    code = <<~CLANG
      BPF_ARRAY(arr, u64, 1);

      int noop(void *ctx)
      {
        return 0;
      }
    CLANG

    @module = BCC.new(text: code)
  end

  def test_integer_write_uses_leaf_size
    table = @module['arr']
    table[0] = 0

    v = table[0]
    assert_equal(0, v.to_bcc_value)
  end
end
