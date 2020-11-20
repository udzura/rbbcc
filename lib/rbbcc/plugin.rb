module RbBCC
  module Plugin
    ScriptLocation = Struct.new(:name, :location)

    def self.scripts
      @scripts ||= []
    end

    def self.find_script_name(name)
      scripts.find{|s|
        s.name == name || "#{s.name}.rb" == name
      }&.location
    end

    def self.register!
      caller_loc = caller[0].split(':')[0]
      plugin_loc = File.expand_path("../../script", caller_loc)
      unless File.directory?(plugin_loc)
        raise "Cannot find a script directory #{plugin_loc}. Maybe an invalid project"
      end

      found = Dir.glob("#{plugin_loc}/*.rb")
                .map{|path| ScriptLocation.new File.basename(path, '.rb'), path }
      self.scripts.concat found
      self.scripts
    end
  end
end
