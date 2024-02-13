require 'rbbcc/consts'
require 'rbbcc/table'
require 'rbbcc/symbol_cache'
require 'rbbcc/debug'

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
    class << self
      def _find_file(filename)
        if filename
          unless File.exist?(filename)
            t = File.expand_path "../#{filename}", $0
            if File.exist?(t)
              filename = t
            else
              raise "Could not find file #{filename}"
            end
          end
        end
        return filename
      end

      def ksym(addr, show_module: false, show_offset: false)
        self.sym(addr, -1, show_module: show_module, show_offset: show_offset, demangle: false)
      end

      def ksymname(name)
        SymbolCache.resolve_global(name)
      end

      def support_raw_tracepoint
        # kernel symbol "bpf_find_raw_tracepoint"
        # indicates raw_tracepint support
        ksymname("bpf_find_raw_tracepoint") || ksymname("bpf_get_raw_tracepoint")
      end

      def get_kprobe_functions(event_re)
        blacklist = []
        fns = []
        File.open(File.expand_path("../kprobes/blacklist", TRACEFS), "rb") do |blacklist_f|
          blacklist = blacklist_f.each_line.map { |line|
            line.rstrip.split[1]
          }.uniq
        end
        in_init_section = 0
        in_irq_section = 0
        File.open("/proc/kallsyms", "rb") do |avail_file|
          avail_file.each_line do |line|
            t, fn = line.rstrip.split[1,2]
            # Skip all functions defined between __init_begin and
            # __init_end
            if in_init_section == 0
              if fn == '__init_begin'
                in_init_section = 1
                next
              elsif in_init_section == 1
                if fn == '__init_end'
                  in_init_section = 2
                  next
                end
              end
              # Skip all functions defined between __irqentry_text_start and
              # __irqentry_text_end
              if in_irq_section == 0
                if fn == '__irqentry_text_start'
                  in_irq_section = 1
                  next
                elsif in_irq_section == 1
                  if fn == '__irqentry_text_end'
                    in_irq_section = 2
                    next
                  end
                end
              end
              # All functions defined as NOKPROBE_SYMBOL() start with the
              # prefix _kbl_addr_*, blacklisting them by looking at the name
              # allows to catch also those symbols that are defined in kernel
              # modules.
              if fn.start_with?('_kbl_addr_')
                next
              # Explicitly blacklist perf-related functions, they are all
              # non-attachable.
              elsif fn.start_with?('__perf') || fn.start_with?('perf_')
                next
              # Exclude all gcc 8's extra .cold functions
              elsif fn =~ /^.*\.cold\.\d+$/
                next
              end
              if %w(t w).include?(t.downcase) \
                 && /#{event_re}/ =~ fn \
                 && !blacklist.include?(fn)
                fns << fn
              end
            end
          end
        end
        fns = fns.uniq
        return fns.empty? ? nil : fns
      end

      def check_path_symbol(module_, symname, addr, pid)
        sym = Clib::BCCSymbol.malloc
        c_pid = pid == -1 ? 0 : pid
        if Clib.bcc_resolve_symname(module_, symname, (addr || 0x0), c_pid, nil, sym) < 0
          raise("could not determine address of symbol %s" % symname)
        end
        module_path = Clib.__extract_char sym.module
        # XXX: need to free char* in ruby ffi?
        Clib.bcc_procutils_free(sym.module)
        return module_path, sym.offset
      end

      def decode_table_type(desc)
        return desc if desc.is_a?(String)
        anon = []
        fields = []
        # e.g. ["bpf_stacktrace", [["ip", "unsigned long long", [127]]], "struct_packed"]
        name, typedefs, data_type = desc
        typedefs.each do |field|
          case field.size
          when 2
            fields << "#{decode_table_type(field[1])} #{field[0]}"
          when 3
            ftype = field.last
            if ftype.is_a?(Array)
              fields << "#{decode_table_type(field[1])}[#{ftype[0]}] #{field[0]}"
            elsif ftype.is_a?(Integer)
              warn("Warning: Ruby fiddle does not support bitfield member, ignoring")
              warn("Adding member `#{field[1]} #{field[0]}:#{ftype}'")
              fields << "#{decode_table_type(field[1])} #{field[0]}"
            elsif %w(union struct struct_packed).in?(ftype)
              name = field[0]
              if name.empty?
                name = "__anon%d" % anon.size
                anon << name
              end
              # FIXME: nested struct
              fields << "#{decode_table_type(field)} #{name}"
            else
              raise("Failed to decode type #{field.inspect}")
            end
          else
            raise("Failed to decode type #{field.inspect}")
          end
        end
        c = nil
        if data_type == "union"
          c = Fiddle::Importer.union(fields)
        else
          c = Fiddle::Importer.struct(fields)
        end

        fields.each do |field|
          md = /^char\[(\d+)\] ([_a-zA-Z0-9]+)/.match(field)
          if md
            c.alias_method "__super_#{md[2]}", md[2]
            c.define_method md[2] do
              # Split the char[] in the place where the first \0 appears
              raw = __send__("__super_#{md[2]}")
              raw = raw[0...raw.index(0)] if raw.index(0)
              raw.pack("c*")
            end
          end
        end

        c.define_singleton_method :original_desc do
          desc
        end
        c.define_singleton_method :fields do
          fields
        end
        orig_name = c.inspect
        c.define_singleton_method :inspect do
          orig_name.sub /(?=>$)/, " original_desc=#{desc.inspect}" rescue super
        end
        c
      end

      def sym(addr, pid, show_module: false, show_offset: false, demangle: true)
        # FIXME: case of typeofaddr.find('bpf_stack_build_id')
        #s = Clib::BCCSymbol.malloc
        #b = Clib::BCCStacktraceBuildID.malloc
        #b.status = addr.status
        #b.build_id = addr.build_id
        #b.u = addr.offset
        #Clib.bcc_buildsymcache_resolve(BPF.bsymcache, b, s)

        name, offset_, module_ = SymbolCache.cache(pid).resolve(addr, demangle)
        offset = (show_offset && name) ? ("+0x%x" % offset_) : ""
        name = name || "[unknown]"
        name = name + offset
        module_ = (show_module && module_) ? " [#{File.basename.basename(module_)}]" : ""
        return name + module_
      end

      def attach_raw_socket(fn, dev)
        unless fn.is_a?(Hash)
          raise "arg 1 must be of BPF.Function Hash"
        end
        sock = Clib.bpf_open_raw_sock(dev)
        if sock < 0
          raise SystemCallError.new("Failed to open raw device %s" % dev, Fiddle.last_error)
        end

        res = Clib.bpf_attach_socket(sock, fn[:fd])
        if res < 0
          raise SystemCallError.new("Failed to attach BPF to device %s" % dev, Fiddle.last_error)
        end
        fn[:sock] = sock
        fn
      end
    end

    def initialize(text: "", src_file: nil, hdr_file: nil, debug: 0, cflags: [], usdt_contexts: [], allow_rlimit: 0, dev_name: nil)
      @kprobe_fds = {}
      @uprobe_fds = {}
      @tracepoint_fds = {}
      @raw_tracepoint_fds = {}

      if src_file
        src_file = BCC._find_file(src_file)
        hdr_file = BCC._find_file(hdr_file)
      end

      if src_file && src_file.end_with?(".b")
        @module = Clib.bpf_module_create_b(src_file, hdr_file, debug, dev_name)
      else
        if src_file
          text = File.read(src_file)
        end

        @usdt_contexts = usdt_contexts
        if code = gen_args_from_usdt
          text = code + text
        end


        cflags_safe = if cflags.empty? or !cflags[-1].nil?
                        cflags + [nil]
                      else
                        cflags
                      end

        @module = Clib.do_bpf_module_create_c_from_string(
          text,
          debug,
          cflags_safe.pack("p*"),
          cflags_safe.size,
          allow_rlimit,
          dev_name
        )
      end
      @funcs = {}
      @tables = {}
      @perf_buffers = {}
      @_ringbuf_manager = nil

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
    attr_reader :module, :perf_buffers

    def gen_args_from_usdt
      ptr = Clib.bcc_usdt_genargs(@usdt_contexts.map(&:context).pack('J*'), @usdt_contexts.size)
      code = ""
      if !ptr || ptr.null?
        return nil
      end

      Clib.__extract_char ptr
    end

    def load_func(func_name, prog_type, device: nil)
      if @funcs.keys.include?(func_name)
        return @funcs[func_name]
      end

      log_level = 0
      fd = Clib.do_bcc_func_load(@module, prog_type, func_name,
             Clib.bpf_function_start(@module, func_name),
             Clib.bpf_function_size(@module, func_name),
             Clib.bpf_module_license(@module),
             Clib.bpf_module_kern_version(@module),
             log_level, nil, 0, device);
      if fd < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      fnobj = {fd: fd, name: func_name}
      @funcs[func_name] = fnobj
      return fnobj
    end

    def attach_tracepoint(tp: "", tp_re: "", fn_name: "")
      fn = load_func(fn_name, BPF::TRACEPOINT)
      tp_category, tp_name = tp.split(':')
      fd = Clib.bpf_attach_tracepoint(fn[:fd], tp_category, tp_name)
      if fd < 0
        raise SystemCallError.new("Failed to attach BPF program #{fn_name} to tracepoint #{tp}", Fiddle.last_error)
      end
      Util.debug "Attach: #{tp}"
      @tracepoint_fds[tp] = fd
      self
    end

    def attach_raw_tracepoint(tp: "", fn_name: "")
      if @raw_tracepoint_fds.keys.include?(tp)
        raise "Raw tracepoint #{tp} has been attached"
      end

      fn = load_func(fn_name, BPF::RAW_TRACEPOINT)
      fd = Clib.bpf_attach_raw_tracepoint(fn[:fd], tp)
      if fd < 0
        raise SystemCallError.new("Failed to attach BPF program #{fn_name} to raw tracepoint #{tp}", Fiddle.last_error)
      end
      Util.debug "Attach: #{tp}"
      @raw_tracepoint_fds[tp] = fd
      self
    end

    def attach_kprobe(event:, fn_name:, event_off: 0)
      fn = load_func(fn_name, BPF::KPROBE)
      ev_name = "p_" + event.gsub(/[\+\.]/, "_")
      fd = Clib.bpf_attach_kprobe(fn[:fd], 0, ev_name, event, event_off, 0)
      if fd < 0
        raise SystemCallError.new("Failed to attach BPF program #{fn_name} to kprobe #{event}", Fiddle.last_error)
      end
      Util.debug "Attach: #{ev_name}"
      @kprobe_fds[ev_name] = fd
      [ev_name, fd]
    end

    def attach_kretprobe(event:, fn_name:, event_re: nil, maxactive: 0)
      # TODO: if event_re ...
      fn = load_func(fn_name, BPF::KPROBE)
      ev_name = "r_" + event.gsub(/[\+\.]/, "_")
      fd = Clib.bpf_attach_kprobe(fn[:fd], 1, ev_name, event, 0, maxactive)
      if fd < 0
        raise SystemCallError.new("Failed to attach BPF program #{fn_name} to kretprobe #{event}", Fiddle.last_error)
      end
      Util.debug "Attach: #{ev_name}"
      @kprobe_fds[ev_name] = fd
      [ev_name, fd]
    end

    def attach_uprobe(name: "", sym: "", addr: nil, fn_name: "", pid: -1)
      path, addr = BCC.check_path_symbol(name, sym, addr, pid)

      fn = load_func(fn_name, BPF::KPROBE)
      ev_name = to_uprobe_evname("p", path, addr, pid)
      fd = Clib.bpf_attach_uprobe(fn[:fd], 0, ev_name, path, addr, pid)
      if fd < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      Util.debug "Attach: #{ev_name}"

      @uprobe_fds[ev_name] = fd
      [ev_name, fd]
    end

    def attach_uretprobe(name: "", sym: "", addr: nil, fn_name: "", pid: -1)
      path, addr = BCC.check_path_symbol(name, sym, addr, pid)

      fn = load_func(fn_name, BPF::KPROBE)
      ev_name = to_uprobe_evname("r", path, addr, pid)
      fd = Clib.bpf_attach_uprobe(fn[:fd], 1, ev_name, path, addr, pid)
      if fd < 0
        raise SystemCallError.new(Fiddle.last_error)
      end
      Util.debug "Attach: #{ev_name}"

      @uprobe_fds[ev_name] = fd
      [ev_name, fd]
    end

    def detach_tracepoint(tp)
      unless @tracepoint_fds.keys.include?(tp)
        raise "Tracepoint #{tp} is not attached"
      end
      res = Clib.bpf_close_perf_event_fd(@tracepoint_fds[tp])
      if res < 0
        raise "Failed to detach BPF from tracepoint"
      end
      tp_category, tp_name = tp.split(':')
      res = Clib.bpf_detach_tracepoint(tp_category, tp_name)
      if res < 0
        raise "Failed to detach BPF from tracepoint"
      end
      @tracepoint_fds.delete(tp)
    end

    def detach_raw_tracepoint(tp)
      unless @raw_tracepoint_fds.keys.include?(tp)
        raise "Raw tracepoint #{tp} is not attached"
      end
      begin
        File.for_fd(@raw_tracepoint_fds[tp]).close
      rescue => e
        warn "Closing fd failed: #{e.inspect}. Ignore and skip"
      end
      @tracepoint_fds.delete(tp)
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

    def num_open_kprobes
      @kprobe_fds.size
    end

    def num_open_uprobes
      @uprobe_fds.size
    end

    def num_open_tracepoints
      @tracepoint_fds.size
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
      ret = []
      while buf = trace_readline
        next if buf.chomp.empty?
        next if buf.start_with? "CPU:"
        task = buf[0..15].lstrip()
        meta, _addr, msg = buf[17..-1].split(": ", 3)
        pid, cpu, flags, ts = meta.split(" ")
        cpu = cpu[1..-2]

        if do_each_line
          do_each_line.call(task, pid, cpu, flags, ts, msg)
        else
          ret = [task, pid, cpu, flags, ts, msg]
          break
        end
      end
      ret
    end

    def cleanup
      @kprobe_fds.each do |k, v|
        detach_kprobe_event(k)
      end

      @uprobe_fds.each do |k, v|
        detach_uprobe_event(k)
      end

      @tracepoint_fds.each do |k, v|
        detach_tracepoint(k)
      end

      @raw_tracepoint_fds.each do |k, v|
        detach_raw_tracepoint(k)
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
        keytype = BCC.decode_table_type(eval(key_desc.to_extracted_char_ptr))
      end

      unless leaftype
        leaf_desc = Clib.bpf_table_leaf_desc(@module, name)
        raise("Failed to load BPF Table #{name} leaf desc") if leaf_desc.null?

        leaftype = BCC.decode_table_type(eval(leaf_desc.to_extracted_char_ptr))
      end
      return Table.new(self, map_id, map_fd, keytype, leaftype, name, reducer: reducer)
    end

    def [](key)
      self.tables[key] ||= get_table(key)
    end

    def []=(key, value)
      self.tables[key] = value
    end

    def perf_buffer_poll(timeout=-1)
      readers = self.perf_buffers.values
      readers.each {|r| r.size = Clib::PerfReader.size }
      pack = readers.map{|r| r[0, Clib::PerfReader.size] }.pack('p*')
      Clib.perf_reader_poll(readers.size, pack, timeout)
    end

    def _open_ring_buffer(map_fd, fn, ctx)
      buf = Clib.bpf_new_ringbuf(map_fd, fn, ctx)
      if !buf
        raise "Could not open ring buffer"
      end
      @_ringbuf_manager ||= buf
    end
    
    def ring_buffer_poll(timeout=-1)
      unless @_ringbuf_manager
        raise "No ring buffers to poll"
      end
      Clib.bpf_poll_ringbuf(@_ringbuf_manager, timeout)
    end
    
    def ksymname(name)
      SymbolCache.resolve_global(name)
    end

    def get_syscall_prefix
      SYSCALL_PREFIXES.each do |prefix|
        if ksymname("%sbpf" % prefix)
          return prefix
        end
      end
      SYSCALL_PREFIXES[0]
    end

    def get_syscall_fnname(name)
      get_syscall_prefix + name
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
        Util.debug "Found fnc: #{func_name}"
        if func_name.start_with?("kprobe__")
          fn = load_func(func_name, BPF::KPROBE)
          attach_kprobe(
            event: fix_syscall_fnname(func_name[8..-1]),
            fn_name: fn[:name]
          )
        elsif func_name.start_with?("kretprobe__")
          fn = load_func(func_name, BPF::KPROBE)
          attach_kretprobe(
            event: fix_syscall_fnname(func_name[11..-1]),
            fn_name: fn[:name]
          )
        elsif func_name.start_with?("tracepoint__")
          fn = load_func(func_name, BPF::TRACEPOINT)
          tp = fn[:name].sub(/^tracepoint__/, "").sub(/__/, ":")
          attach_tracepoint(
            tp: tp,
            fn_name: fn[:name]
          )
        elsif func_name.start_with?("raw_tracepoint__")
          fn = load_func(func_name, BPF::RAW_TRACEPOINT)
          tp = fn[:name].sub(/^raw_tracepoint__/, "")
          attach_raw_tracepoint(
            tp: tp,
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
