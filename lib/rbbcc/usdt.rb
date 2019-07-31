require 'rbbcc/clib'

module RbBCC
  USDTProbe = Struct.new(:binpath, :fn_name, :addr, :pid)

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

    def enumerate_active_probes
      probes = []
      callback = Clib.bind('void _usdt_cb(char *, char *, unsigned long long, int)') do |binpath, fn_name, addr, pid|
        probe = USDTProbe.new(Clib.__extract_char(binpath), Clib.__extract_char(fn_name), addr, pid)
        probes << probe
      end

      Clib.bcc_usdt_foreach_uprobe(@context, callback)

      return probes
    end
  end
end
