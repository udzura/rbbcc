if ENV['RBBCC_DEBUG'] || ENV['BCC_DEBUG']
  module RbBCC
    module Util
      def self.debug(msg)
        puts msg
      end
    end
  end
else
  module RbBCC
    module Util
      def self.debug(msg)
        # nop
      end
    end
  end
end
