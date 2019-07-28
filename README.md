# RbBCC

[![Gem Version](https://badge.fury.io/rb/rbbcc.svg)](https://badge.fury.io/rb/rbbcc)

RbBCC is a port of [BCC](https://github.com/iovisor/bcc) in MRI. See iovisor project page.

![Movie](examples/example.gif)

This gem requires `libbcc.so`. Please install it [following BCC's instruction](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rbbcc'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rbbcc

## Usage

```ruby
require 'rbbcc' 

code = <<CLANG
int kprobe__sys_clone(void *ctx)
{
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
CLANG
RbBCC::BCC.new(text: code).trace_print
```

See examples (both in rbbcc and BCC)

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/udzura/rbbcc.
