require 'rubygems'
require 'rbbcc/plugin'

module RbBCC
  class Invoker
    def initialize(args)
      @command = args.shift
      args.shift if args[0] == '--'
      @args = args
    end

    def run
      plugins = Gem::Specification
                  .find_all
                  .select{|s| s.name =~ /^rbbcc-/ }
                  .map(&:name)
      plugins.each {|n| require n }

      script = RbBCC::Plugin.find_script_name(@command)
      raise Errno::ENOENT, "Script not found: #{@command}" unless script

      binpath = File.readlink "/proc/self/exe"
      exec binpath, *ARGV

      Process.exec binpath, '-rrbbcc', script, *@args
    end
  end
end
