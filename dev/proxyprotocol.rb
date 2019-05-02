class ProxyProtocol
  attr_accessor :source_port, :dest_port
  attr_reader :tvs, :command, :version, :protocol, :addr_family, :protocolv2, :source_addr, :dest_addr
  attr_accessor :signature
  def initialize(arg={})
    @tlvs={}
    @signature = "\r\n\r\n\0\r\nQUIT\n"
    self.command= :PROXY
    self.addr_family= :AF_UNSPEC
    self.protocol= :UNKNOWN
    arg.each do |k,v|
      send "#{k}=", v
    end
  end
  
  def source_addr=(val)
    @source_addr = @addr_family == 0x30 ? val : IPAddr.new(val)
  end
  def dest_addr=(val)
    @dest_addr = @addr_family == 0x30 ? val : IPAddr.new(val)
  end
  def protocol=(val)
    case val.upcase.to_sym
    when :TCP6
      @protocol = :TCP6
      @protocolv2 = 0x01
      self.addr_family=:AF_INET6
    when :TCP4
      @protocol = :TCP4
      @protocolv2 = 0x01
      self.addr_family=:AF_INET
    when :UNKNOWN, :UNSPEC
      @protocol = :UNKNOWN
      @protocolv2 = 0x00
    when :STREAM
      @protocol = :UNKNOWN
      @protocolv2 = 0x01
    when :DGRAM
      @protocol = :UNKNOWN
      @protocolv2 = 0x02
    else
      throw "bad protocol"
    end
  end
  
  def addr_family=(val)
    case val.upcase.to_sym
    when :AF_UNSPEC
      @addr_family=0x00
    when :AF_INET
      @addr_family=0x10
    when :AF_INET6
      @addr_family=0x20
    when :AF_UNIX
      @addr_family=0x30
    else
      throw "bad addr_family"
    end
  end
  
  def command=(val)
    case(val.to_s.upcase.to_sym)
    when :LOCAL
      @command = 0
    when :PROXY
      @command = 1
    else
      @command = val.to_i
    end
  end
  def version=(val)
    @version = val.to_i
  end
  
  def add_tlv(type, val)
    throw "bad type" if type < 0 || type > 255
    @tlvs[type]=val
  end
  
  def to_s
    throw "bad version" unless [1, 2].include? @version
    out = ""
    if @version == 2 #binary
      out << @signature
      out << (0x20 + @command).chr #version and command byte. version is always 0x20
      out << (@addr_family + @protocolv2)
      addrs = ""
      case @addr_family
      when 0x10, 0x20
        addrs << "#{@source_addr.hton}#{@dest_addr.hton}#{[@source_port.to_i].pack("n")}#{[@dest_port.to_i].pack("n")}"
      when 0x30
        addrs << "#{@source_addr.ljust(108,"\0")}#{@dest_addr.ljust(108,"\0")}"
      end
      tlvs_str = ""
      @tlvs.each do |type, val|
        tlvs_str << "#{type.chr}#{[val.length].pack("n")}#{val}"
      end
      out << [addrs.length + tlvs_str.length].pack("n")
      out << addrs
      out << tlvs_str
    else
      out << "PROXY #{@protocol || "UNKNOWN"}"
      if @protocol && @protocol != :UNKNOWN
        out << " #{@source_addr.to_s} #{@dest_addr.to_s} #{@source_port} #{@dest_port}\r\n"
      else
        out << "\r\n"
      end
    end
    out
  end
end
