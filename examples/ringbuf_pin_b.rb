#!/usr/bin/env ruby
require 'rbbcc'
include RbBCC

PIN_PATH = "/sys/fs/bpf/pinned_ringbuf"

type = "struct data_t {
    u32 pid;
    char comm[16];
};"

puts "Process B (Ruby): Initializing consumer client..."
buf = RingBuf.from_pin(PIN_PATH, type, 4)

# ring_buffer listner
buf.open_ring_buffer do |cpu, data, size|
  event = buf.event(data)
  puts "[Process B Captured] PID: #{event.pid.to_s.ljust(6)} | COMMAND: #{event.comm}"
end

puts "\n[Process B Active] Successfully hooked to pinned map (FD: #{buf.map_fd}). Listening for events...\n\n"

begin
  loop do
    buf.ring_buffer_poll()
  end
rescue Interrupt
  puts "\nExiting Process B."
end
