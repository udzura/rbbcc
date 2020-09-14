require 'fiddle'
require 'fiddle/import'

class Fiddle::Pointer
  def bcc_value
    @bcc_value ||= _bcc_value
  end
  alias to_bcc_value bcc_value

  def _bcc_value
    if self.bcc_value_type.is_a?(Class)
      return self.bcc_value_type.new(self)
    end

    case self.bcc_size
    when Fiddle::Importer.sizeof("int")
      self[0, self.size].unpack("i!").first
    when Fiddle::Importer.sizeof("long")
      self[0, self.size].unpack("l!").first
    else
      self[0, self.size].unpack("Z*").first
    end
  end

  def method_missing(name, *a)
    bcc_value.respond_to?(name) ?
      bcc_value.send(name) :
      super
  end

  attr_accessor :bcc_value_type
  attr_writer   :bcc_size
  def bcc_size
    @bcc_size || self.size
  end
end
