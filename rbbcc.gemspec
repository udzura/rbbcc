lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "rbbcc/version"

Gem::Specification.new do |spec|
  spec.name          = "rbbcc"
  spec.version       = RbBCC::VERSION
  spec.authors       = ["Uchio Kondo"]
  spec.email         = ["udzura@udzura.jp"]
  spec.license       = "Apache-2.0"

  spec.summary       = %q{BCC port for MRI}
  spec.description   = %q{BCC port for MRI. See https://github.com/iovisor/bcc}
  spec.homepage      = "https://github.com/udzura/rbbcc"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  #spec.bindir        = "exe"
  #spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
