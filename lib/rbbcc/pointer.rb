module RbBCC
  class Pointer
    def initialize(p, value_type: nil, size: nil)
      @raw_pointer = p
      @size = size || p.size
      @value_type = value_type
    end

    attr_reader :raw_pointer

    def value

    end
  end
end
