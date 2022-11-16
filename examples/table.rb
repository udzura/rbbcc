#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

b = BCC.new(text: <<CLANG)
BPF_HASH(the_table_name, int);
CLANG

table = b.get_table('the_table_name', leaftype: 'int')

table[10] = 1
table[20] = 2
puts table[10].to_bcc_value == 1
puts table[20].to_bcc_value == 2
