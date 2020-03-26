require 'rbbcc/clib'

module RbBCC
  USDTProbe = Struct.new(:binpath, :fn_name, :addr, :pid)

  class USDT
    def initialize(pid: nil, path: nil)
      @pid = pid
      @path = path
      if pid
        @context = Clib.bcc_usdt_new_frompid(pid, path)
      elsif path
        @context = Clib.bcc_usdt_new_frompath(path)
      else
        raise "Either a pid or a binary path must be specified"
      end
      if !@context || @context.null?
        raise SystemCallError.new(Fiddle.last_error)
      end
    end
    attr_reader :pid, :path, :context

    def enable_probe(probe:, fn_name:)
      ret = Clib.bcc_usdt_enable_probe(@context, probe, fn_name)
      if(ret < 0)
        raise SystemCallError.new(Fiddle.last_error)
      end
      ret
    end

    def enumerate_active_probes
      probes = []
      callback = Clib.bind('void _usdt_cb(char *, char *, unsigned long long, int)') do |binpath, fn_name, addr, pid|
        probe = USDTProbe.new(Clib.__extract_char(binpath), Clib.__extract_char(fn_name), addr, pid)
        probes << probe
      end

      Clib.bcc_usdt_foreach_uprobe(@context, callback)

      return probes
    end

    private
    def __del__
      lambda { Clib.bcc_usdt_close(@context); Util.debug("USDT GC'ed.") }
    end
  end
end

at_exit do
  ObjectSpace.each_object(RbBCC::USDT) do |o|
    o.send(:__del__).call
  end
end
