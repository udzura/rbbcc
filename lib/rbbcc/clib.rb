require 'fiddle/import'

module RbBCC
  module Clib
    def self.__extract_char(ptr)
      return nil if ptr.null?
      idx = 0
      while ptr[idx, 1] != "\x00"
        idx += 1
      end
      ptr.size = idx + 1
      ptr.to_s
    end

    def self.libbcc_version=(ver)
      @@libbcc_version ||= Gem::Version.new(ver)
    end

    def self.libbcc_version
      @@libbcc_version
    end

    def self.libbcc_version_gteq?(ver)
      @@libbcc_version >= Gem::Version.new(ver)
    end

    extend Fiddle::Importer
    targets = %w(0.17.0 0.16.0 0.15.0 0.14.0 0.13.0 0.12.0 0.11.0 0.10.0)
    if default_load = ENV['LIBBCC_VERSION']
      targets.unshift(default_load)
      targets.uniq!
    end

    targets.each do |to_load|
      begin
        dlload "libbcc.so.#{to_load}"
        self.libbcc_version = to_load
        break
      rescue Fiddle::DLError => e
        if targets.last == to_load
          raise LoadError, "no target libbcc to load"
        end
      end
    end
    typealias "size_t", "int"

    extern 'void * bpf_module_create_c_from_string(char *, unsigned int, char **, int, long)'
    extern 'void * bpf_module_create_b(char *filename, char *proto_filename, unsigned int flags, char *dev_name)'
    extern 'int bpf_num_functions(void *)'
    extern 'char * bpf_function_name(void *, int)'
    extern 'void bpf_module_destroy(void *)'

    if libbcc_version_gteq?("0.11.0")
      extern 'int bcc_func_load(
                  void *program, int prog_type, const char *name,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned int kern_version,
                  int log_level, char *log_buf, unsigned int log_buf_size,
                  const char *dev_name)'
      def self.do_bcc_func_load(mod, prog_type, name, insns, len, license, kver, loglv, buf, buf_size, device)
        bcc_func_load(mod, prog_type, name, insns, len, license, kver, loglv, buf, buf_size, device)
      end
    else
      extern 'int bcc_func_load(void *, int, char *, void *, int, char *, unsigned int, int, char *, unsigned int)'
      def self.do_bcc_func_load(mod, prog_type, name, insns, len, license, kver, loglv, buf, buf_size, device)
        bcc_func_load(mod, prog_type, name, insns, len, license, kver, loglv, buf, buf_size)
      end
    end

    extern 'void * bpf_function_start(void *, char *)'
    extern 'int bpf_function_size(void *, char *)'
    extern 'char * bpf_module_license(void *)'
    extern 'unsigned int bpf_module_kern_version(void *)'
    extern 'int bpf_table_fd(void *, char *)'
    extern 'int bpf_table_id(void *, char *)'
    extern 'int bpf_table_type_id(void *, int)'
    extern 'int bpf_table_flags_id(void *, int)'
    extern 'char * bpf_table_key_desc(void *, char *)'
    extern 'char * bpf_table_leaf_desc(void *, char *)'
    extern 'int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)'
    extern 'int bpf_delete_elem(int fd, void *key)'

    extern 'int bpf_attach_kprobe(int, int, char *, char *, unsigned long, int)'
    extern 'int bpf_detach_kprobe(char *)'
    extern 'int bpf_attach_uprobe(int, int, char *, char *, unsigned long, int)'
    extern 'int bpf_detach_uprobe(char *)'
    extern 'int bpf_attach_tracepoint(int progfd, char *tp_category, char *tp_name)'
    extern 'int bpf_detach_tracepoint(char *tp_category, char *tp_name)'
    extern 'int bpf_attach_raw_tracepoint(int progfd, char *tp_name)'
    extern 'int bpf_open_perf_event(unsigned int, unsigned long, int, int)'
    extern 'int bpf_close_perf_event_fd(int)'
    extern 'int bpf_get_first_key(int, void *, int)'
    extern 'int bpf_get_next_key(int, void *, void *)'
    extern 'int bpf_lookup_elem(int fd, void *key, void *value)'
    extern 'size_t bpf_table_max_entries_id(void *program, size_t id)'

    # FIXME: This size of struct will change in future version
    # and no struct member info in header. This is hacky
    PerfReader = struct(
      [
        "void * raw_cb",
        "void * lost_cb",
        "void * cb_cookie",
        "void * buf",
        "int buf_size",
        "void * base",
        "int rb_use_state",
        "int rb_read_tid",
        "int page_size",
        "int page_cnt",
        "int fd"
      ]
    )

    #typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
    #typedef void (*perf_reader_lost_cb)(void *cb_cookie, uint64_t lost);
    extern 'void * bpf_open_perf_buffer(void *raw_cb, void *lost_cb, void *cb_cookie, int pid, int cpu, int page_cnt)'
    extern 'int perf_reader_fd(void *reader)'
    extern 'size_t bpf_perf_event_fields(void *program, const char *event)'
    extern 'char * bpf_perf_event_field(void *program, const char *event, size_t i)'

    extern 'void * bcc_usdt_new_frompid(int, char *)'
    extern 'void * bcc_usdt_new_frompath(char *path)'
    extern 'int bcc_usdt_enable_probe(void *, char *, char *)'
    extern 'char * bcc_usdt_genargs(void **, int)'
    extern 'void bcc_usdt_foreach_uprobe(void *, void *)'
    extern 'void bcc_usdt_close(void *usdt)'
    BCCSymbol = struct([
                         "const char *name",
                         "const char *demangle_name",
                         "const char *module",
                         "unsigned long offset"
                 ])
    BCCSymbolOption = struct([
                               'int use_debug_file',
                               'int check_debug_file_crc',
                               'unsigned int use_symbol_type'
                             ])
    BCCIPOffsetUnion = union(['unsigned long long offset', 'unsigned long long ip'])
    BCCStacktraceBuildID = \
      struct([
               'unsigned int status',
               'unsigned char[20] build_id',
               'unsigned long long u' # truly union
             ])
    extern 'int bcc_resolve_symname(char *module, char *symname,
                        unsigned long long addr, int pid,
                        struct bcc_symbol_option* option,
                        struct bcc_symbol *sym)'
    extern 'void * bcc_symcache_new(int, void *)'
    extern 'void bcc_free_symcache(void *, int)'
    extern 'int bcc_symcache_resolve(void *, unsigned long, void *)'
    extern 'int bcc_symcache_resolve_no_demangle(void *, unsigned long, void *)'
    extern 'int bcc_symcache_resolve_name(void *, char *, char *, unsigned long long *)'
    extern 'void bcc_symbol_free_demangle_name(struct bcc_symbol *sym)'

    extern 'int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout)'

    extern 'void bcc_procutils_free(const char *ptr)'

    extern 'int bpf_open_raw_sock(const char *name)'
    extern 'int bpf_attach_socket(int sockfd, int progfd)'
  end
end

class Fiddle::Pointer
  def to_extracted_char_ptr
    RbBCC::Clib.__extract_char(self)
  end
end
