#!/usr/bin/env ruby
# frozen_string_literal: true

require "rbbcc"
include RbBCC

begin
  require "http/2"
rescue LoadError
  # Fallback for local vendor source
  local_http2_lib = File.expand_path("../.agent/sources/http-2/lib", __dir__)
  $LOAD_PATH.unshift(local_http2_lib) unless $LOAD_PATH.include?(local_http2_lib)
  require "http/2"
end

FRAME_TYPE_NAMES = {
  0x0 => "DATA",
  0x1 => "HEADERS",
  0x2 => "PRIORITY",
  0x3 => "RST_STREAM",
  0x4 => "SETTINGS",
  0x5 => "PUSH_PROMISE",
  0x6 => "PING",
  0x7 => "GOAWAY",
  0x8 => "WINDOW_UPDATE",
  0x9 => "CONTINUATION"
}.freeze

HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b
HTTP1_METHODS = %w[GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT].freeze

BPF_TEXT = <<~BPF
  #include <uapi/linux/ptrace.h>

  #define MAX_PAYLOAD_SIZE 1024

  struct event_t {
      u32 pid;
      char event_name[8];
      unsigned char payload[MAX_PAYLOAD_SIZE];
      u32 data_len;
      s32 read_ret;
  };

  BPF_RINGBUF_OUTPUT(events, 256);

  int trace_ssl_write(struct pt_regs *ctx) {
      u32 tgid = bpf_get_current_pid_tgid() >> 32;

      const char *user_buf = (const char *)PT_REGS_PARM2(ctx);
      u64 num = (u64)PT_REGS_PARM3(ctx);
      if (!user_buf || num <= 0) return 0;

      struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
      if (!event) return 0;

      event->pid = tgid;
      __builtin_memcpy(event->event_name, "ssl_w", 6);

      u32 len = num > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : (u32)num;
      event->data_len = len;

      event->read_ret = bpf_probe_read_user(event->payload, len, user_buf);
      if (event->read_ret < 0) {
          event->data_len = 0;
      }

      events.ringbuf_submit(event, 0);
      return 0;
  }
BPF

def hex_ascii_dump(payload, width: 16)
  lines = []
  payload.bytes.each_slice(width).with_index do |slice, idx|
    offset = idx * width
    hex = slice.map { |b| "%02x" % b }.join(" ")
    ascii = slice.map { |b| b >= 32 && b <= 126 ? b.chr : "." }.join
    lines << format("%04x  %-#{width * 3 - 1}s  %s", offset, hex, ascii)
  end
  lines.join("\n")
end

def payload_from_event(event)
  raw = event.payload
  bytes = case raw
          when String
            raw.b
          when Array
            raw.map { |v| v & 0xff }.pack("C*")
          else
            if raw.respond_to?(:to_a)
              raw.to_a.map { |v| v & 0xff }.pack("C*")
            else
              raw.to_s.b
            end
          end

  len = [event.data_len.to_i, bytes.bytesize].min
  bytes.byteslice(0, len) || "".b
end

def parse_http2_frames(payload)
  frames = []
  i = 0
  total = payload.bytesize

  while i + 9 <= total
    length_bytes = payload.byteslice(i, 3).bytes
    length = (length_bytes[0] << 16) | (length_bytes[1] << 8) | length_bytes[2]
    frame_type = payload.getbyte(i + 3)
    flags = payload.getbyte(i + 4)
    stream_id = payload.byteslice(i + 5, 4).unpack1("N") & 0x7fff_ffff
    i += 9
    break if i + length > total

    frame_payload = payload.byteslice(i, length)
    i += length
    frames << [frame_type, flags, stream_id, frame_payload]
  end

  frames
end

def extract_headers_fragment(frame_type, flags, frame_payload)
  return frame_payload if frame_type == 0x9 # CONTINUATION
  return nil unless frame_type == 0x1 # HEADERS only

  start_idx = 0
  end_idx = frame_payload.bytesize

  if (flags & 0x08) != 0 # PADDED
    return nil if end_idx.zero?

    pad_len = frame_payload.getbyte(0)
    start_idx += 1
    end_idx = [start_idx, end_idx - pad_len].max
  end

  if (flags & 0x20) != 0 # PRIORITY
    return nil if start_idx + 5 > end_idx

    start_idx += 5
  end

  frame_payload.byteslice(start_idx, end_idx - start_idx) || "".b
end

def decode_pseudo_headers_with_hpack(header_block, decompressor)
  pairs = decompressor.decode(header_block.dup)
  pseudo = {}
  pairs.each do |k, v|
    next unless k == ":method" || k == ":path"

    pseudo[k] = v
  end
  pseudo
rescue StandardError => e
  { ":error" => e.message }
end

def maybe_http1_summary(payload)
  text = payload.force_encoding(Encoding::UTF_8)
  first_line = text.split("\r\n", 2).first
  return nil if first_line.nil? || first_line.empty?

  if HTTP1_METHODS.any? { |m| first_line.start_with?("#{m} ") }
    return ["request", first_line]
  end

  if first_line.start_with?("HTTP/1.1 ") || first_line.start_with?("HTTP/1.0 ")
    return ["response", first_line]
  end

  nil
rescue ArgumentError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError
  nil
end

def main
  puts "SSL HTTP tracer (Ruby + ring buffer) を初期化中..."

  b = BCC.new(text: BPF_TEXT)

  libssl_path = ENV.fetch("LIBSSL_PATH", "/usr/lib/aarch64-linux-gnu/libssl.so.3")
  b.attach_uprobe(name: libssl_path, sym: "SSL_write", fn_name: "trace_ssl_write")
  puts "Attached uprobe: SSL_write (#{libssl_path})"

  decompressor = HTTP2::Header::Decompressor.new
  continuation_state = {}

  b["events"].open_ring_buffer do |_ctx, data, _size|
    event = b["events"].event(data)
    event_name = event.event_name.to_s
    next unless event_name == "ssl_w"

    payload = payload_from_event(event)
    puts "[PID: #{event.pid}] len=#{event.data_len} read_ret=#{event.read_ret}"
    next if event.data_len.to_i <= 0

    summary = maybe_http1_summary(payload)
    if summary
      kind, line = summary
      puts "[HTTP/1.x #{kind}] #{line}"
      puts hex_ascii_dump(payload)
      next
    end

    rest = payload
    if rest.start_with?(HTTP2_PREFACE)
      puts "[H2] client preface detected"
      rest = rest.byteslice(HTTP2_PREFACE.bytesize..) || "".b
    end

    frames = parse_http2_frames(rest)
    if frames.empty?
      puts hex_ascii_dump(payload)
      next
    end

    frames.each do |frame_type, flags, stream_id, frame_payload|
      frame_name = FRAME_TYPE_NAMES.fetch(frame_type, "UNKNOWN(#{frame_type})")
      puts "[H2] type=#{frame_name} flags=0x#{format('%02x', flags)} stream=#{stream_id} len=#{frame_payload.bytesize}"

      case frame_type
      when 0x1 # HEADERS
        fragment = extract_headers_fragment(frame_type, flags, frame_payload)
        if fragment.nil?
          puts "[HPACK] parse_error=invalid HEADERS payload"
          next
        end

        key = [event.pid.to_i, stream_id]
        if (flags & 0x04) != 0 # END_HEADERS
          pseudo = decode_pseudo_headers_with_hpack(fragment, decompressor)
          if pseudo.key?(":error")
            puts "[HPACK] decode_error=#{pseudo[":error"]}"
          else
            puts "[HPACK] :method=#{pseudo.fetch(":method", "?")} :path=#{pseudo.fetch(":path", "?")}"
          end
        else
          continuation_state[key] = fragment.dup
          puts "[HPACK] collecting CONTINUATION fragments"
        end
      when 0x9 # CONTINUATION
        key = [event.pid.to_i, stream_id]
        fragment = extract_headers_fragment(frame_type, flags, frame_payload)
        unless continuation_state.key?(key)
          puts "[HPACK] note=orphan CONTINUATION frame"
          next
        end

        continuation_state[key] << fragment
        next if (flags & 0x04).zero?

        header_block = continuation_state.delete(key)
        pseudo = decode_pseudo_headers_with_hpack(header_block, decompressor)
        if pseudo.key?(":error")
          puts "[HPACK] decode_error=#{pseudo[":error"]}"
        else
          puts "[HPACK] :method=#{pseudo.fetch(":method", "?")} :path=#{pseudo.fetch(":path", "?")}"
        end
      end
    end
  end

  puts "監視開始。Ctrl+C で終了"
  loop do
    b.ring_buffer_poll(100)
  rescue Interrupt
    puts "\n終了します。"
    exit(0)
  end
end

main if $PROGRAM_NAME == __FILE__
