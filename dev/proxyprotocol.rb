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
  def tlv
    @tlvs
  end
  def add_tlv(type, val)
    throw "bad type" if type < 0 || type > 255
    @tlvs[type]=val
  end
  
  def add_checksum(opt={})
    @custom_checksum = opt[:custom][0..3].ljust(4, "\0") if opt[:custom]
    opt[:bad] ? bad_checksum! : good_checksum!
    add_tlv 0x03, "\0\0\0\0"
  end
  def bad_checksum!
    @bad_checksum = true
    @tlvs[0x03] = "\0\0\0\0"
  end
  def good_checksum!
    @custom_checksum = nil
    @bad_checksum = nil
  end
  
  def checksum
    if @custom_checksum
      crc = @custom_checksum
    else
      crc = Digest::CRC32c.checksum(self.to_s no_checksum: true)
      crc -= 1 if @bad_checksum
      crc = [crc].pack("N")
    end
    @tlvs[0x03]=crc
  end
  
  def to_s(opt={})
    throw "bad version" unless [1, 2].include? @version
    out = ""
    if @version == 2 #binary
      checksum if @tlvs[0x03] && !opt[:no_checksum]
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
        tlvs_str << "#{type.chr}#{[val.length].pack("n")}#{(type == 0x03 && opt[:no_checksum]) ? "\0\0\0\0" : val}"
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


module HTTP
  class Options
    attr_accessor :proxy_protocol_header
  end
  class Connection
    alias :__initialize :initialize
    def initialize(req, options)
      @proxy_protocol_header=options.proxy_protocol_header
      __initialize req, options
    end
    alias :__send_proxy_connect_request :send_proxy_connect_request
    def send_proxy_connect_request(req)
      ret = __send_proxy_connect_request(req)
      @socket << @proxy_protocol_header.to_s if @proxy_protocol_header
      ret
    end
  end
end

class HTTP2Client
  class Response
    attr_accessor :status, :headers, :body
    def initialize(headers, body)
      @headers = {}
      binding.pry if headers.nil?
      headers.each { |h| @headers[h[0]]=h[1] }
      @status = @headers[":status"].to_i
      @body = body
    end
  end
  def initialize(uri, opt={})
    @pph = opt[:proxy_protocol_header]
    @uri = URI.parse(uri)
    @tcp = TCPSocket.new @uri.host, @uri.port
    
    @tcp << @pph.to_s if @pph
    
    if @uri.scheme == "https"
      @ssl_ctx = OpenSSL::SSL::SSLContext.new
      @ssl_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @ssl_ctx.alpn_protocols = [ "h2".freeze ]
      @sock = OpenSSL::SSL::SSLSocket.new(@tcp, @ssl_ctx)
      @sock.sync_close = true
      @sock.hostname = @uri.hostname
      @sock.connect
    else
      @sock = @tcp
    end
    @client = HTTP2::Client.new
    @client.on(:frame) {|bytes| @sock.print bytes; @sock.flush}
  end
  def get(url)
    throw "http/2 client already closed" if @closed
    stream = @client.new_stream
    request_done = false
    stream.on(:close) do
      request_done = true
    end
    headers = nil
    body = ""
    head = {
      ':scheme' => @uri.scheme,
      ':method' => 'GET',
      ':authority' => [@uri.host, @uri.port].join(':'),
      ':path' => url,
      'accept' => "*/*"
    }
    stream.on(:data) {|d| body << d}
    stream.on(:headers) {|h| headers = h}
      
    stream.headers(head, end_stream: true)
    while !request_done && !@sock.closed? && !@sock.eof?
      @client << @sock.read_nonblock(1024)
    end
    return Response.new(headers, body)
  end
  def close
    @sock.close
    @closed = true
  end
end
