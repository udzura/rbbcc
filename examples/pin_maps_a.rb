#!/usr/bin/env ruby
#
# pin_maps_a.rb
# Program A: create HashMap/ArrayMap, hook execve, count up, and pin maps.
#
# Usage (root):
#   sudo ruby examples/pin_maps_a.rb --pin-dir /sys/fs/bpf/rbbcc_pin_demo

require 'rbbcc'
require 'optparse'
require 'fileutils'

include RbBCC

BPF_TEXT = <<~CLANG
  BPF_HASH(pin_hash_map, u32, u64, 1024);
  BPF_ARRAY(pin_array_map, u64, 1);

  int trace_execve(void *ctx) {
    u64 zero = 0;
    u32 pid = bpf_get_current_pid_tgid();
    u32 idx = 0;
    u64 *hval;
    u64 *aval;

    hval = pin_hash_map.lookup_or_try_init(&pid, &zero);
    if (hval) {
      __sync_fetch_and_add(hval, 1);
    }

    aval = pin_array_map.lookup(&idx);
    if (aval) {
      __sync_fetch_and_add(aval, 1);
    }

    return 0;
  }
CLANG

options = {
  pin_dir: '/sys/fs/bpf/rbbcc_pin_demo'
}

OptionParser.new do |opts|
  opts.banner = 'Usage: pin_maps_a.rb [options]'

  opts.on('--pin-dir DIR', 'Pin directory under bpffs') do |v|
    options[:pin_dir] = v
  end
end.parse!

b = BCC.new(text: BPF_TEXT)
b.attach_kprobe(
  event: b.get_syscall_fnname('execve'),
  fn_name: 'trace_execve'
)

hash_map = b['pin_hash_map']
array_map = b['pin_array_map']

# Initialize global counter slot.
array_map[0] = 0

FileUtils.mkdir_p(options[:pin_dir])
hash_path = File.join(options[:pin_dir], 'pin_hash_map')
array_path = File.join(options[:pin_dir], 'pin_array_map')

File.unlink(hash_path) if File.exist?(hash_path)
File.unlink(array_path) if File.exist?(array_path)

BCC.pin!(hash_map.map_fd, hash_path)
BCC.pin!(array_map.map_fd, array_path)

puts 'Pinned maps created.'
puts "  hash map:  #{hash_path}"
puts "  array map: #{array_path}"
puts 'kprobe attached to execve. Run some commands in another terminal.'
puts 'Press Ctrl-C to stop Program A.'

begin
  loop do
    sleep 1
    total = array_map[0]&.to_bcc_value || 0
    puts "execve total count: #{total}"
  end
rescue Interrupt
  puts '\nStopping Program A...'
end
