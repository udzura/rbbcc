require 'fiddle'
require 'fiddle/import'

class Fiddle::Pointer
  def to_bcc_value
    case self.size
    when Fiddle::Importer.sizeof("int")
      self[0, self.size].unpack("i!").first
    when Fiddle::Importer.sizeof("long")
      self[0, self.size].unpack("l!").first
    else
      self[0, self.size].unpack("Z*").first
    end
  end
end
