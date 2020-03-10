# Projects Using RbBCC

## bpfql

[bpfql](https://github.com/udzura/bpfql) is a tool to run an eBPF tracing query, using YAML or Ruby DSL.

```ruby
BPFQL do
  select "*"
  from "tracepoint:random:urandom_read"
  where "comm", is: "ruby"
end
```

```console
$ sudo bundle exec bpfql examples/random.rb
Found fnc: tracepoint__random__urandom_read
Attach: random:urandom_read
TS                 COMM             PID    GOT_BITS POOL_LEFT INPUT_LEFT
0.000000000        ruby             32485  128      0        2451
0.002465663        ruby             32485  128      0        2451
^CExiting bpfql...
```

See [its repo](https://github.com/udzura/bpfql) for more details.

## rack-ebpf and rack application tracing

[rack-ebpf](https://github.com/udzura/rack-ebpf) is a rack middleware that invoke USDT probes every time start/end the requests.

Combine this rack middleware and `rack-ebpf-run` command, we can trace and analyze system stats per request.

e.g.

* Count of syscall invocations(like read, write) per request
* Consumed time for syscall ops(like read, write) per request
* Created Ruby objects per request, using Ruby itself's USDT (this requires ruby itself as `--enable-dtrace` build)

For detailed usage, see [rack-ebpf's repo](https://github.com/udzura/rack-ebpf)

----

Also we're going to prepare some BCC tools made with Ruby. TBA!
