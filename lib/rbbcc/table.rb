require 'rbbcc/clib'
require 'fiddle'
require 'enumerator'
require 'rbbcc/disp_helper'
require 'rbbcc/cpu_helper'

module RbBCC
  module Table
    BPF_MAP_TYPE_HASH = 1
    BPF_MAP_TYPE_ARRAY = 2
    BPF_MAP_TYPE_PROG_ARRAY = 3
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
    BPF_MAP_TYPE_PERCPU_HASH = 5
    BPF_MAP_TYPE_PERCPU_ARRAY = 6
    BPF_MAP_TYPE_STACK_TRACE = 7
    BPF_MAP_TYPE_CGROUP_ARRAY = 8
    BPF_MAP_TYPE_LRU_HASH = 9
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
    BPF_MAP_TYPE_LPM_TRIE = 11
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
    BPF_MAP_TYPE_HASH_OF_MAPS = 13
    BPF_MAP_TYPE_DEVMAP = 14
    BPF_MAP_TYPE_SOCKMAP = 15
    BPF_MAP_TYPE_CPUMAP = 16
    BPF_MAP_TYPE_XSKMAP = 17
    BPF_MAP_TYPE_SOCKHASH = 18

    def self.new(bpf, map_id, map_fd, keytype, leaftype, name, **kwargs)
      ttype = Clib.bpf_table_type_id(bpf.module, map_id)
      case ttype
      when BPF_MAP_TYPE_HASH
        HashTable.new(bpf, map_id, map_fd, keytype, leaftype)
      when BPF_MAP_TYPE_ARRAY
        ArrayTable.new(bpf, map_id, map_fd, keytype, leaftype)
      when BPF_MAP_TYPE_PERF_EVENT_ARRAY
        PerfEventArray.new(bpf, map_id, map_fd, keytype, leaftype, name: name)
      when BPF_MAP_TYPE_STACK_TRACE
        StackTrace.new(bpf, map_id, map_fd, keytype, leaftype)
      else
        raise "Unknown table type #{ttype}"
      end
    end
  end

  class TableBase
    include Fiddle::Importer
    include CPUHelper
    include Enumerable

    def initialize(bpf, map_id, map_fd, keytype, leaftype, name: nil)
      @bpf, @map_id, @map_fd, @keysize, @leafsize = \
                                        bpf, map_id, map_fd, sizeof(keytype), sizeof(leaftype)
      @leaftype = leaftype
      @ttype = Clib.bpf_table_type_id(self.bpf.module, self.map_id)
      @flags = Clib.bpf_table_flags_id(self.bpf.module, self.map_id)
      @name = name
    end
    attr_reader :bpf, :map_id, :map_fd, :keysize, :leafsize, :leaftype, :ttype, :flags, :name

    def next(key)
      next_key = Fiddle::Pointer.malloc(self.keysize)

      if !key
        res = Clib.bpf_get_first_key(self.map_fd, next_key,
                                     next_key.size)
      else
        unless key.is_a?(Fiddle::Pointer)
          raise TypeError, key.inspect
        end
        res = Clib.bpf_get_next_key(self.map_fd, key,
                                    next_key)
      end

      if res < 0
        raise StopIteration
      end

      return next_key
    end

    def [](key)
      leaf = Fiddle::Pointer.malloc(self.leafsize)
      res = Clib.bpf_lookup_elem(self.map_fd, key, leaf)
      if res < 0
        nil
      end
      return leaf
    end

    def fetch(key)
      self[key] || raise(KeyError, "key not found")
    end

    def []=(key, leaf)
      res = Clib.bpf_update_elem(self.map_fd, key, leaf, 0)
      if res < 0
        raise SystemCallError.new("Could not update table", Fiddle.last_error)
      end
      res
    end

    def each_key
      k = nil
      keys = []
      loop do
        k = self.next(k)
        keys << k
        yield k
      end
      keys
    end

    def each_value
      each_key {|key| yield(self[key]) if self[key] }
    end

    def each_pair
      each_key {|key| yield(key, self[key]) if self[key] }
    end
    alias each each_pair

    def values
      enum_for(:each_value).to_a
    end

    def items
      enum_for(:each_pair).to_a
    end

    def print_log2_hist(val_type="value",
                        section_header: "Bucket ptr",
                        section_print_fn: nil,
                        bucket_fn: nil,
                        strip_leading_zero: false,
                        bucket_sort_fn: nil)
      if structured_key?
        raise NotImplementedError
      else
        vals = Array.new($log2_index_max) { 0 }
        each_pair do |k, v|
          vals[k.to_bcc_value] = v.to_bcc_value
        end
        RbBCC.print_log2_hist(vals, val_type, strip_leading_zero)
      end
      nil
    end

    def print_linear_hist(val_type="value",
                          section_header: "Bucket ptr",
                          section_print_fn: nil,
                          bucket_fn: nil,
                          bucket_sort_fn: nil)
      if structured_key?
        raise NotImplementedError
      else
        vals = Array.new($linear_index_max) { 0 }
        each_pair do |k, v|
          vals[k.to_bcc_value] = v.to_bcc_value
        end
        RbBCC.print_linear_hist(vals, val_type)
      end
      nil
    end

    def structured_key?
      false # TODO: implement me in the future
    end

    private
    def byref(value, size=sizeof("int"))
      pack_fmt = case size
                 when sizeof("int") ; "i!"
                 when sizeof("long"); "l!"
                 else               ; "Z*"
                 end
      ptr = Fiddle::Pointer.malloc(size)
      ptr[0, size] = [value].pack(pack_fmt)
      ptr
    end
  end

  class HashTable < TableBase
  end

  class ArrayTable < TableBase
    def initialize(bpf, map_id, map_fd, keytype, leaftype, name: nil)
      super
      @max_entries = Clib.bpf_table_max_entries_id(bpf.module, map_id)
    end

    # We now emulate the Array class of Ruby
    def size
      @max_entries
    end
    alias length size

    def [](key)
      super(normalize_key(key))
    end

    def each(&b)
      each_value do |v|
        b.call(v.to_bcc_value)
      end
    end

    private
    def normalize_key(key)
      case key
      when Fiddle::Pointer
        key
      when Integer
        byref(key, keysize)
      else
        raise KeyError, "#{key.inspect} must be integer or pointor"
      end
    end
  end

  class PerfEventArray < TableBase
    def initialize(bpf, map_id, map_fd, keytype, leaftype, name: nil)
      super
      @open_key_fds = {}
      @event_class = nil
      @_cbs = {}
      @_open_key_fds = {}
    end

    def event(data)
      @event_class ||= get_event_class
      ev = @event_class.malloc
      Fiddle::Pointer.new(ev.to_ptr)[0, @event_class.size] = data[0, @event_class.size]
      return ev
    end

    def open_perf_buffer(page_cnt: 8, lost_cb: nil, &callback)
      if page_cnt & (page_cnt - 1) != 0
        raise "Perf buffer page_cnt must be a power of two"
      end

      get_online_cpus.each do |i|
        _open_perf_buffer(i, callback, page_cnt, lost_cb)
      end
    end

    private
    def get_event_class
      ct_mapping = {
        's8': 'char',
        'u8': 'unsined char',
        's8 *': 'char *',
        's16': 'short',
        'u16': 'unsigned short',
        's32': 'int',
        'u32': 'unsigned int',
        's64': 'long long',
        'u64': 'unsigned long long'
      }

      array_type = /(.+) \[([0-9]+)\]$/
      fields = []
      num_fields = Clib.bpf_perf_event_fields(self.bpf.module, @name)
      num_fields.times do |i|
        field = Clib.__extract_char(Clib.bpf_perf_event_field(self.bpf.module, @name, i))
        field_name, field_type = *field.split('#')
        if field_type =~ /enum .*/
          field_type = "int" #it is indeed enum...
        end
        if _field_type = ct_mapping[field_type.to_sym]
          field_type = _field_type
        end

        m = array_type.match(field_type)
        if m
          field_type = "#{m[1]}[#{m[2]}]"
          fields << [field_type, field_name].join(" ")
        else
          fields << [field_type, field_name].join(" ")
        end
      end
      klass = Fiddle::Importer.struct(fields)
      if fields.find {|f| f =~ /^char\[(\d+)\] ([_a-zA-Z0-9]+)/ }
        size = $1
        m = Module.new do
          define_method $2 do
            super().pack("c#{size}").sub(/\0+$/, "")
          end
        end
        klass.prepend m
      end
      klass
    end

    def _open_perf_buffer(cpu, callback, page_cnt, lost_cb)
      # bind("void raw_cb_callback(void *, void *, int)")
      fn = Fiddle::Closure::BlockCaller.new(
        Fiddle::TYPE_VOID,
        [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
      ) do |_dummy, data, size|
        begin
          callback.call(cpu, data, size)
        rescue => e
          if Fiddle.last_error == 32 # EPIPE
            exit
          else
            raise e
          end
        end
      end
      lost_fn = Fiddle::Closure::BlockCaller.new(
        Fiddle::TYPE_VOID,
        [Fiddle::TYPE_VOIDP, Fiddle::TYPE_ULONG]
      ) do |_dummy, lost|
        begin
          lost_cb(lost)
        rescue => e
          if Fiddle.last_error == 32 # EPIPE
            exit
          else
            raise e
          end
        end
      end if lost_cb
      reader = Clib.bpf_open_perf_buffer(fn, lost_fn, nil, -1, cpu, page_cnt)
      if !reader || reader.null?
        raise "Could not open perf buffer"
      end
      fd = Clib.perf_reader_fd(reader)

      self[byref(cpu, @keysize)] = byref(fd, @leafsize)
      self.bpf.perf_buffers[[object_id, cpu]] = reader
      @_cbs[cpu] = [fn, lost_fn]
      @_open_key_fds[cpu] = -1
    end
  end

  class StackTrace < TableBase
    MAX_DEPTH = 127
    BPF_F_STACK_BUILD_ID = (1<<5)
    BPF_STACK_BUILD_ID_EMPTY =  0 #can't get stacktrace
    BPF_STACK_BUILD_ID_VALID = 1 #valid build-id,ip
    BPF_STACK_BUILD_ID_IP = 2 #fallback to ip

    def get_stack(stack_id)
      key = stack_id.is_a?(Fiddle::Pointer) ? stack_id : byref(stack_id, @keysize)
      leaftype.new(self[stack_id])
    end

    def walk(stack_id, resolve: nil, &blk)
      addrs = if (flags & BPF_F_STACK_BUILD_ID).nonzero?
                get_stack(stack_id).trace[0..MAX_DEPTH]
              else
                get_stack(stack_id).ip[0..MAX_DEPTH]
              end
      addrs.each do |addr|
        break if addr.zero?
        if resolve
          blk.call(resolve.call(addr))
        else
          blk.call(addr)
        end
      end
    end
  end
end
