#!/usr/bin/env ruby
# Original task_switch.rb Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

require 'rbbcc'
include RbBCC

b = BCC.new(src_file: "16-task_switch.c")
b.attach_kprobe(event: "finish_task_switch", fn_name: "count_sched")

# generate many schedule events
100.times { sleep 0.01 }

b["stats"].each do |_k, v|
  k = _k[0, 8].unpack("i! i!") # Handling pointer without type!!
  puts("task_switch[%5d->%5d]=%u" % [k[0], k[1], v.to_bcc_value])
end
