#!/usr/bin/env ruby
#
# dns_blocker.rb  Block DNS queries for a specified domain using TC/eBPF.
#
# Uses TC clsact qdisc and attaches a SCHED_CLS BPF program to the
# egress path.  Because pyroute2 is unavailable in Ruby, the BPF
# program is pinned to /sys/fs/bpf and attached via the `tc` shell
# command.
#
# Usage (must be run as root):
#   ruby dns_blocker.rb -i eth0 -d ruby-lang.org
#

require 'rbbcc'
require 'optparse'

include RbBCC

def domain_to_payload_check_code(domain)
  # Convert a domain name to DNS wire format (length-prefixed labels)
  # For example, "example.com" becomes "\\x07example\\x03com\\x00"
  dns_expression = domain.split('.').map { |label| "#{label.length.chr}#{label}" }.join + "\x00"
  c_check_code = dns_expression.chars.map.with_index { |c, i| "payload[offset+#{i}] == #{c.ord}" }.join(" &&\n  ")
  c_check_code
end

BPF_TEXT = ->(domain) {
  <<~CLANG
  // Some Hack :(
  #define BPF_LOAD_ACQ -1
  #define BPF_STORE_REL -2

  #include <uapi/linux/bpf.h>
  #include <uapi/linux/pkt_cls.h>
  #include <linux/if_ether.h>
  #include <linux/ip.h>
  #include <linux/udp.h>

  int block_dns(struct __sk_buff *skb) {
      void *data     = (void *)(long)skb->data;
      void *data_end = (void *)(long)skb->data_end;

      // Ethernet header check
      struct ethhdr *eth = data;
      if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
      if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

      // IP header check
      struct iphdr *ip = (void *)(eth + 1);
      if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
      if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

      // UDP header check
      struct udphdr *udp = (void *)ip + (ip->ihl * 4);
      if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

      // Only care about port 53 (DNS) egress queries
      if (udp->dest != bpf_htons(53)) return TC_ACT_OK;

      // DNS payload boundary check: DNS header (12 bytes) + "example.com" wire format (13 bytes)
      unsigned char *payload = (unsigned char *)(udp + 1);
      if ((void *)(payload + 12 + 13) > data_end) return TC_ACT_OK;

      // "example.com" in DNS wire format: \\x07example\\x03com\\x00
      int offset = 12;
      if (#{domain_to_payload_check_code(domain)}) {
          bpf_trace_printk("Blocked DNS query for #{domain}\\n");
          return TC_ACT_SHOT;
      }

      return TC_ACT_OK;
  }
  CLANG
  }

PIN_PATH = "/sys/fs/bpf/dns_blocker_prog"

def setup_tc(interface)
  # Run idempotently
  system("sudo tc qdisc add dev #{interface} clsact 2>/dev/null")
end

def attach_tc(interface)
  system(
    "sudo tc filter add dev #{interface} egress" +
    " bpf pinned #{PIN_PATH} da",
    exception: true
  )
end

def cleanup_tc(interface)
  # Run idempotently
  system("sudo tc qdisc del dev #{interface} clsact 2>/dev/null")
  File.unlink(PIN_PATH) if File.exist?(PIN_PATH)
end

options = {domain: "example.com"}
OptionParser.new { |opts|
  opts.banner = "Usage: #{$0} -i INTERFACE"
  opts.on("-i", "--interface IFACE", "Network interface to monitor (e.g. eth0)") do |v|
    options[:interface] = v
  end
  opts.on("-d", "--domain DOMAIN", "Domain to block (default: example.com)") do |v|
    options[:domain] = v
  end
}.parse!

iface = options[:interface] || abort("Error: Interface name is required")

# Clean up any leftover state from a previous run
cleanup_tc(iface)

puts "[*] Compiling BPF program..."
b = BCC.new(text: BPF_TEXT.call(options[:domain]))
fn = b.load_func("block_dns", BPF::SCHED_CLS)

# Pin the loaded BPF program so that `tc` can reference it by path
puts "[*] Pinning BPF program to #{PIN_PATH} ..."
BCC.pin!(fn, PIN_PATH)

# Set up clsact qdisc and attach the pinned program to egress
puts "[*] Attaching TC filter to #{iface} (egress) ..."
setup_tc(iface)
attach_tc(iface)

puts "[*] Blocking DNS queries for #{options[:domain]} on #{iface}. Press Ctrl+C to stop."
begin
  b.trace_print
rescue Interrupt
  puts "\n[*] Shutting down..."
ensure
  cleanup_tc(iface)
  puts "[*] Cleanup done."
end
