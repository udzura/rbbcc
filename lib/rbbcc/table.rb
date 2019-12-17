require 'rbbcc/clib'
require 'fiddle'
require 'enumerator'
require 'rbbcc/disp_helper'

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
      when BPF_MAP_TYPE_ARRAY
        ArrayTable.new(bpf, map_id, map_fd, keytype, leaftype)
      when BPF_MAP_TYPE_PERF_EVENT_ARRAY
        PerfEventArray.new(bpf, map_id, map_fd, keytype, leaftype, name: name)
      else
        raise "Unknown table type #{ttype}"
      end
    end
  end

  class TableBase
    include Fiddle::Importer
    include Enumerable

    def initialize(bpf, map_id, map_fd, keytype, leaftype, name: nil)
      @bpf, @map_id, @map_fd, @keysize, @leafsize = \
        bpf, map_id, map_fd, sizeof(keytype), sizeof(leaftype)
      @ttype = Clib.bpf_table_type_id(self.bpf.module, self.map_id)
      @flags = Clib.bpf_table_flags_id(self.bpf.module, self.map_id)
      @name = name
    end
    attr_reader :bpf, :map_id, :map_fd, :keysize, :leafsize, :ttype, :flags, :name

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

    # def []=(key, newvalue)
    # end

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
      pack_fmt = case sizeof
                 when sizeof("int") ; "i!"
                 when sizeof("long"); "l!"
                 else               ; "Z*"
                 end
      ptr = Fiddle::Pointer.malloc(size)
      ptr[0, size] = [value].pack(pack_fmt)
      ptr
    end
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
  end
end
