#!/usr/bin/env ruby
#
# pin_maps_b.rb
# Program B: open pinned HashMap/ArrayMap with from_pin and read/update values.
#
# Usage (root):
#   sudo ruby examples/pin_maps_b.rb --pin-dir /sys/fs/bpf/rbbcc_pin_demo

require 'rbbcc'
require 'optparse'

include RbBCC

options = {
  pin_dir: '/sys/fs/bpf/rbbcc_pin_demo'
}

OptionParser.new do |opts|
  opts.banner = 'Usage: pin_maps_b.rb [options]'

  opts.on('--pin-dir DIR', 'Pin directory under bpffs') do |v|
    options[:pin_dir] = v
  end
end.parse!

hash_path = File.join(options[:pin_dir], 'pin_hash_map')
array_path = File.join(options[:pin_dir], 'pin_array_map')

unless File.exist?(hash_path) && File.exist?(array_path)
  abort("Pinned map files are missing. Run pin_maps_a.rb first: #{options[:pin_dir]}")
end

# Explicitly pass key/leaf type and size; no type detection is performed.
hash_map = HashTable.from_pin(
  hash_path,
  'unsigned int',
  'unsigned long long',
  keysize: 4,
  leafsize: 8
)
array_map = ArrayTable.from_pin(
  array_path,
  'unsigned int',
  'unsigned long long',
  keysize: 4,
  leafsize: 8
)

puts 'Loaded pinned maps.'
puts "  hash map fd:  #{hash_map.map_fd}"
puts "  array map fd: #{array_map.map_fd}"
puts "  hash ttype:   #{hash_map.ttype}"
puts "  array ttype:  #{array_map.ttype}"

puts 'Read existing values:'
puts "  hash[1] = #{hash_map[1]&.to_bcc_value.inspect}"
puts "  hash[2] = #{hash_map[2]&.to_bcc_value.inspect}"
puts "  array[0] = #{array_map[0]&.to_bcc_value.inspect}"
puts "  array[1] = #{array_map[1]&.to_bcc_value.inspect}"

hash_map[3] = 1
array_map[0] = (array_map[0]&.to_bcc_value || 0) + 1

puts 'Updated values:'
puts "  hash[3] = #{hash_map[3]&.to_bcc_value.inspect}"
puts "  array[0] = #{array_map[0]&.to_bcc_value.inspect}"

puts 'Iterate hash entries:'
hash_map.each_pair do |k, v|
  puts "  #{k.to_bcc_value} => #{v.to_bcc_value}"
end
