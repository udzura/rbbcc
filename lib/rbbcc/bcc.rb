require 'rbbcc/consts'

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
      @kprobe_fds = []
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

      unless @module
        raise "BPF module not created"
      end

      trace_autoload!

      @usdt_contexts.each do |usdt|
        Clib.bcc_usdt_foreach_uprobe(usdt.context, Clib::UsdtUprobeAttachCallback)
      end
    end

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
      puts "Attach: #{event}"
      @kprobe_fds << fd
    end

    def tracefile
      @tracefile ||= File.open("#{TRACEFS}/trace_pipe", "rb")
    end

    def trace_readline
      tracefile.readline(1024).rstrip
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
          # TODO resolution from sym cache
          return SYSCALL_PREFIXES[0] + name.sub(prefix, "")
        end
      end
      return name
    end
  end
end
