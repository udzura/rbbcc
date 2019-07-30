require 'rbbcc/usdt'
include RbBCC
usdt = USDT.new(pid: 13909)
usdt.enable_probe(probe: 'mruby', fn_name: 'test')
Clib.bcc_usdt_foreach_uprobe(usdt.context, Clib::UsdtUprobeAttachCallback)

