require 'fiddle/import'

module RbBCC
  module CLib
    extend Fiddle::Importer
    dlload "libbcc.so.0"

    extern 'void * bpf_module_create_c_from_string(char *, unsigned int, char **, int, long)'
  end
end
