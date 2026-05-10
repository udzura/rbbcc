#!/usr/bin/env ruby
#
# lsm_sockblock.rb  Monitor/block AF_ALG socket_create via BPF LSM.
#
# This example uses LSM_PROBE(socket_create) and a BPF_ARRAY map for mode:
#   0 = preview (log only)
#   1 = block   (return -EPERM)
#
# The config map is pinned to bpffs so mode can be changed externally.
#
# Usage:
#   sudo ruby examples/lsm_sockblock.rb
#   sudo ruby examples/lsm_sockblock.rb --mode block
#   sudo ruby examples/lsm_sockblock.rb --pin-path /sys/fs/bpf/my_config_map

require 'optparse'
require 'socket'
require 'rbbcc'

include RbBCC

PROGRAM = <<~CLANG
  #include <linux/lsm_hooks.h>
  #include <linux/socket.h>
  #include <uapi/asm-generic/errno-base.h>

  struct data_t {
      u32 pid;
      int family;
      int type;
      int is_warning;
      int is_blocked;
      char comm[16];
  };

  BPF_PERF_OUTPUT(events);
  BPF_ARRAY(config_map, u32, 1);

  LSM_PROBE(socket_create, int family, int type, int protocol, int kern)
  {
      u32 pid = bpf_get_current_pid_tgid() >> 32;
      struct data_t data = {};

      u32 key = 0;
      u32 *mode = config_map.lookup(&key);
      int is_block_mode = (mode && *mode == 1);

      data.pid = pid;
      data.family = family;
      data.type = type;
      bpf_get_current_comm(&data.comm, sizeof(data.comm));

      if (family == AF_ALG) {
          data.is_blocked = is_block_mode;
          data.is_warning = 1;
          events.perf_submit(ctx, &data, sizeof(data));

          if (is_block_mode) {
              return -EPERM;
          }
      } else {
          data.is_blocked = 0;
          data.is_warning = 0;
          events.perf_submit(ctx, &data, sizeof(data));
      }

      return 0;
  }
CLANG

options = {
  mode: "preview",
  pin_path: "/sys/fs/bpf/rbbcc_lsm_config_map"
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [--mode preview|block] [--pin-path PATH]"

  opts.on("--mode MODE", ["preview", "block"], "Operation mode (default: preview)") do |v|
    options[:mode] = v
  end

  opts.on("--pin-path PATH", "bpffs pin path (default: /sys/fs/bpf/rbbcc_lsm_config_map)") do |v|
    options[:pin_path] = v
  end
end.parse!

mode_value = (options[:mode] == "block") ? 1 : 0

families = Socket.constants.grep(/^AF_/).each_with_object({}) do |name, h|
  begin
    v = Socket.const_get(name)
    h[v] = name.to_s if v.is_a?(Integer)
  rescue NameError
    next
  end
end

types = Socket.constants.grep(/^SOCK_/).each_with_object({}) do |name, h|
  begin
    v = Socket.const_get(name)
    h[v] = name.to_s if v.is_a?(Integer)
  rescue NameError
    next
  end
end

begin
  b = BCC.new(text: PROGRAM)

  config = b["config_map"]
  config[0] = mode_value

  File.unlink(options[:pin_path]) if File.exist?(options[:pin_path])
  BCC.pin!(config.map_fd, options[:pin_path])

  puts "LSM BPF started in #{options[:mode].upcase} mode."
  puts "Pinned config map: #{options[:pin_path]}"
  puts "Tracing AF_ALG socket_create... Press Ctrl-C to exit."

  b["events"].open_perf_buffer do |cpu, data, size|
    event = b["events"].event(data)
    family = families.fetch(event.family, "AF_UNKNOWN(#{event.family})")
    stype = types.fetch(event.type, "SOCK_UNKNOWN(#{event.type})")

    puts "PID: #{event.pid.to_s.ljust(7)} | COMM: #{event.comm.to_s.ljust(15)} | FAMILY: #{family.ljust(14)} | TYPE: #{stype}"

    next if event.is_warning == 0

    mode_str = (event.is_blocked == 1) ? "BLOCK" : "PREVIEW"
    status = (event.is_blocked == 1) ? "REJECTED" : "WARNING"
    puts "[#{mode_str}] #{status}: PID #{event.pid} (#{event.comm}) tried AF_ALG socket creation."
  end

  loop do
    b.perf_buffer_poll
  end
rescue Interrupt
  puts "\nStopping..."
ensure
  File.unlink(options[:pin_path]) if File.exist?(options[:pin_path])
end
