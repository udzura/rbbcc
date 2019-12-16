require 'rbbcc/consts'
require 'rbbcc/table'
require 'rbbcc/symbol_cache'

module RbBCC
  SYSCALL_PREFIXES = [
    "sys_",
    "__x64_sys_",
    "__x32_compat_sys_",
    "__ia32_compat_sys_",
    "__arm64_sys_",
  ]
  TRACEFS = "/sys/kernel/debug/tracing"

  class BCC
    def initialize(text:, debug: 0, cflags: [], usdt_contexts: [], allow_rlimit: 0)
      @kprobe_fds = {}
      @uprobe_fds = {}
      @usdt_contexts = usdt_contexts
      if code = gen_args_from_usdt
        text = code + text
      end

      @module = Clib.bpf_module_create_c_from_string(
        text,
        debug,
        cflags.pack('p*'),
        cflags.size,
        allow_rlimit
      )
      @funcs = {}
      @tables = {}

      unless @module
        raise "BPF module not created"
      end

      trace_autoload!

      @usdt_contexts.each do |usdt|
        usdt.enumerate_active_probes.each do |probe|
          attach_uprobe(name: probe.binpath, fn_name: probe.fn_name, addr: probe.addr, pid: probe.pid)
        end
      end

      at_exit { self.cleanup }
    end
    attr_reader :module

    def gen_args_from_usdt
      ptr = Clib.bcc_usdt_genargs(@usdt_contexts.map(&:context).pack('J*'), @usdt_contexts.size)
      code = ""
      if !ptr || ptr.null?
        return nil
      end

      idx = 0
      while ptr[idx, 1] != "\x00"
        idx += 1
      end
      ptr.size = idx + 1
      ptr.to_s
    end

    def load_func(func_name, prog_type)
      if @funcs.keys.include?(func_name)
        return @funcs[func_name]
      end

      log_level = 0
      fd = Clib.bcc_func_load(@module, prog_type, func_name,
             Clib.bpf_function_start(@module, func_name),
             Clib.bpf_function_size(@module, func_name),
             Clib.bpf_module_license(@module),
             Clib.bpf_module_kern_version(@module),
             log_level, nil, 0);
      if fd < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      fnobj = {fd: fd, name: func_name}
      @funcs[func_name] = fnobj
      return fnobj
    end

    def attach_kprobe(event:, fn_name:, event_off: 0)
      fn = load_func(fn_name, BPF::KPROBE)
      ev_name = "p_" + event.gsub(/[\+\.]/, "_")
      fd = Clib.bpf_attach_kprobe(fn[:fd], 0, ev_name, event, event_off, 0)
      if fd < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      puts "Attach: #{ev_name}"
      @kprobe_fds[ev_name] = fd
      [ev_name, fd]
    end

    def attach_uprobe(name: "", sym: "", addr: nil, fn_name: "", pid: -1)
      fn = load_func(fn_name, BPF::KPROBE)
      ev_name = to_uprobe_evname("p", name, addr, pid)
      fd = Clib.bpf_attach_uprobe(fn[:fd], 0, ev_name, name, addr, pid)
      if fd < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      puts "Attach: #{ev_name}"

      @uprobe_fds[ev_name] = fd
      [ev_name, fd]
    end

    def detach_kprobe_event(ev_name)
      unless @kprobe_fds.keys.include?(ev_name)
        raise "Event #{ev_name} not registered"
      end
      if Clib.bpf_close_perf_event_fd(@kprobe_fds[ev_name]) < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      if Clib.bpf_detach_kprobe(ev_name) < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      @kprobe_fds.delete(ev_name)
    end

    def detach_uprobe_event(ev_name)
      unless @uprobe_fds.keys.include?(ev_name)
        raise "Event #{ev_name} not registered"
      end
      if Clib.bpf_close_perf_event_fd(@uprobe_fds[ev_name]) < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      if Clib.bpf_detach_uprobe(ev_name) < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      @uprobe_fds.delete(ev_name)
    end

    def tracefile
      @tracefile ||= File.open("#{TRACEFS}/trace_pipe", "rb")
    end

    def trace_readline
      tracefile.readline(1024)
    end

    def trace_print(fmt: nil)
      loop do
        if fmt
        # TBD
        else
          line = trace_readline
        end
        puts line
        $stdout.flush
      end
    end

    def trace_fields(&do_each_line)
      while buf = trace_readline
        next if buf.start_with? "CPU:"
        task = buf[0..15].lstrip()
        meta, _addr, msg = buf[17..-1].split(": ")
        pid, cpu, flags, ts = meta.split(" ")
        cpu = cpu[1..-2]

        do_each_line.call(task, pid, cpu, flags, ts, msg)
      end
    end

    def cleanup
      @kprobe_fds.each do |k, v|
        detach_kprobe_event(k)
      end

      @uprobe_fds.each do |k, v|
        detach_uprobe_event(k)
      end

      if @module
        Clib.bpf_module_destroy(@module)
      end
    end

    attr_reader :tables
    def get_table(name, keytype: nil, leaftype: nil, reducer: nil)
      map_id = Clib.bpf_table_id(@module, name)
      map_fd = Clib.bpf_table_fd(@module, name)

      raise KeyError, "map not found" if map_fd < 0
      unless keytype
        key_desc = Clib.bpf_table_key_desc(@module, name)
        raise("Failed to load BPF Table #{name} key desc") if key_desc.null?
        keytype = eval(key_desc.to_extracted_char_ptr) # XXX: parse as JSON?
      end

      unless leaftype
        leaf_desc = Clib.bpf_table_leaf_desc(@module, name)
        raise("Failed to load BPF Table #{name} leaf desc") if leaf_desc.null?
        leaftype = eval(leaf_desc.to_extracted_char_ptr)
      end
      return Table.new(self, map_id, map_fd, keytype, leaftype, name, reducer: reducer)
    end

    def [](key)
      self.tables[key] ||= get_table(key)
    end

    def []=(key, value)
      self.tables[key] = value
    end

    private
    def trace_autoload!
      (0..Clib.bpf_num_functions(@module)).each do |i|
        func_name = ""
        _func_name = Clib.bpf_function_name(@module, i)
        if _func_name && !_func_name.null?
          idx = 0
          while _func_name[idx, 1] != "\x00"
            idx += 1
          end
          _func_name.size = idx + 1
          func_name = _func_name.to_s
        else
          next
        end
        puts "Found fnc: #{func_name}"
        if func_name.start_with?("kprobe__")
          fn = load_func(func_name, BPF::KPROBE)
          attach_kprobe(
            event: fix_syscall_fnname(func_name[8..-1]),
            fn_name: fn[:name]
          )
        end
      end
    end

    def fix_syscall_fnname(name)
      SYSCALL_PREFIXES.each do |prefix|
        if name.start_with?(prefix)
          real = SYSCALL_PREFIXES.find { |candidate|
            SymbolCache.resolve_global(name.sub(prefix, candidate))
          }
          unless real
            real = prefix
          end

          return name.sub(prefix, real)
        end
      end
      return name
    end

    def to_uprobe_evname(prefix, path, addr, pid)
      if pid == -1
        return "%s_%s_0x%x" % [prefix, path.gsub(/[^_a-zA-Z0-9]/, "_"), addr]
      else
        return "%s_%s_0x%x_%d" % [prefix, path.gsub(/[^_a-zA-Z0-9]/, "_"), addr, pid]
      end
    end
  end
end
