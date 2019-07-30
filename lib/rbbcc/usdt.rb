require 'rbbcc/clib'

module RbBCC
  class USDT
    # TODO path:
    def initialize(pid:)
      @pid = pid
      @context = Clib.bcc_usdt_new_frompid(pid, nil)
      if !@context || @context.null?
        raise SystemCallError.new(Fiddle.last_error)
      end
    end
    attr_reader :pid, :context

    def enable_probe(probe:, fn_name:)
      ret = Clib.bcc_usdt_enable_probe(@context, probe, fn_name)
      if(ret < 0)
        raise SystemCallError.new(Fiddle.last_error)
      end
      ret
    end
  end
end
