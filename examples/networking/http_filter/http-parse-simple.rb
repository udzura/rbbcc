#!/usr/bin/env ruby
#
#Original http-parse-simple.py in invisor/bcc
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#Ruby version by Uchio Kondo, License follows
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

require 'rbbcc'
require 'socket'
require 'io/nonblock'
include RbBCC

def usage
  puts <<-USAGE
USAGE: #{$0} [-i <if_name>]
  USAGE
  exit
end

interface = "eth0"

if ARGV.size == 2
  if ARGV[0] == '-i'
    interface = ARGV[1]
  else
    usage
  end
elsif ARGV.size != 0
  usage
end

puts("binding socket to '%s'" % interface)

bpf = BCC.new(src_file: "http-parse-simple.c")

function_http_filter = bpf.load_func("http_filter", BPF::SOCKET_FILTER)

BCC.attach_raw_socket(function_http_filter, interface)

socket_fd = function_http_filter[:sock]

sock = Socket.for_fd socket_fd
sock.nonblock = false

ETH_HLEN = 14
loop do
  packet_str = sock.sysread(2048)
  packet_bytearray = packet_str.bytes

  # See original comment...
  #calculate packet total length
  total_length = packet_bytearray[ETH_HLEN + 2]                #load MSB
  total_length = total_length << 8                             #shift MSB
  total_length = total_length + packet_bytearray[ETH_HLEN + 3] #add LSB

  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

  ((payload_offset-1)..(packet_bytearray.size-1)).each do |i|
    if packet_bytearray[i] == 0x0A
      if packet_bytearray[i-1] == 0x0D
        break
      end
    end
    print(packet_bytearray[i].chr)
  end
  puts
end
