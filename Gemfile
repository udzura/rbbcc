source "https://rubygems.org"

# Specify your gem's dependencies in rbbcc.gemspec
gemspec

gem "bundler", "~> 2.0"
gem "rake", "~> 13.0"
gem "pry", "~> 0.12"
gem "minitest", ">= 5"

group :omnibus_package do
  gem "appbundler"
  gem "specific_install"
end

group :plugin_dev do
  gem "rbbcc-hello", git: "https://github.com/udzura/rbbcc-hello.git"
end
