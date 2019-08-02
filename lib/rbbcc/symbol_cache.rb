require 'rbbcc/clib'

module RbBCC
  class SymbolCache
    class << self
      def caches
        @caches ||= {}
      end

      def cache(pid)
        pid = -1 if pid < 0 && pid != -1
        caches[pid] ||= SymbolCache.new(pid)
        caches[pid]
      end
      alias [] cache
    end

    def initialize(pid)
      @cache = Clib.bcc_symcache_new(pid, nil)
    end

    def resolve(addr, demangle)
      sym = Clib::BCCSymcache.malloc
      ret = if demangle
              Clib.bcc_symcache_resolve(@cache, addr, sym)
            else
              Clib.bcc_symcache_resolve_no_demangle(@cache, addr, sym)
            end
      if res < 0
        return [nil, addr, nil]
      end

      if demangle
        name_res = sym.demangle_name
        # Clib.bcc_symbol_free_demangle_name(sym)
      else
        name_res = sym.name
      end

      return [name_res, sym.offset, Clib.__extract_char(sym.module)]
    end

    def resolve_name(_module, name)
      addr_p = Fiddle::Pointer.malloc(Fiddle::SIZEOF_UINTPTR_T)
      if Clib.bcc_symcache_resolve_name(@cache, _module, name, addr_p) < 0
        return false
      end
      return addr_p
    end
  end
end
