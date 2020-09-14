require 'fiddle'
require 'fiddle/import'

class Fiddle::Pointer
  # fixme: handling struct
  def to_bcc_value
    case self.bcc_size
    when Fiddle::Importer.sizeof("int")
      self[0, self.size].unpack("i!").first
    when Fiddle::Importer.sizeof("long")
      self[0, self.size].unpack("l!").first
    else
      self[0, self.size].unpack("Z*").first
    end
  end

  attr_accessor :bcc_value_type
  attr_writer   :bcc_size
  def bcc_size
    @bcc_size || self.size
  end
end
