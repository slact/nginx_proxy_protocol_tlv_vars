#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'

require 'minitest'
require 'minitest/reporters'
require "minitest/autorun"

require "http"
require "net-http2"
require "pry"
require_relative "proxyprotocol.rb"

class BetterSpecReporter < Minitest::Reporters::SpecReporter
  def before_test(test)
    test_name = test.name.gsub(/^test_: /, 'test:')
    print pad_test(test_name)
    print yellow("...")
  end
  def record_print_status(test)
    print ANSI::Code.left(4)
    print_colored_status(test)
    print(" (%.2fs)" % test.time) unless test.time.nil?
    puts
  end
end
Minitest::Reporters.use! BetterSpecReporter.new
require 'securerandom'
require "optparse"

$server_url="http://127.0.0.1:8082"
$verbose=false
$ordered_tests = false

extra_opts = []
orig_args = ARGV.dup

opt=OptionParser.new do |opts|
  opts.on("--server SERVER (#{$server_url})", "server url."){|v| $server_url=v}
  opts.on("--verbose", "set Accept header") do |v| 
    verbose = true
    Typhoeus::Config.verbose = true
  end
  opts.on_tail('-h', '--help', 'Show this message!!!!') do
    puts opts
    raise OptionParser::InvalidOption , "--help"
  end
  opts.on("--ordered", "order tests alphabetically"){$ordered_tests = true}
end

begin
  opt.parse!(ARGV)
rescue OptionParser::InvalidOption => e
  extra_opts << e.args
  retry
end

(orig_args & ( ARGV | extra_opts.flatten )).each { |arg| ARGV << arg }

def url(part="")
  part=part[1..-1] if part[0]=="/"
  "#{$server_url}/#{part}"
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

module NetHttp2
  class Client
    attr_accessor :proxy_protocol_header
  end
  PROXY_SETTINGS_KEYS << :proxy_protocol_header
  module Socket
    class << self
      alias :__tcp_socket :tcp_socket
      def tcp_socket(uri, options)
        sock = __tcp_socket(uri, options)
        sock << options[:proxy_protocol_header] if options[:proxy_protocol_header]
        sock
      end
    end
  end
end

RAW_PRIVATELINK_PP2_HEADER = [
  0x0d, 0x0a, 0x0d, 0x0a, # Start of Sig
  0x00, 0x0d, 0x0a, 0x51,
  0x55, 0x49, 0x54, 0x0a, # End of Sig
  0x21, 0x11, 0x00, 0x54, # ver_cmd, fam and len
  0xac, 0x1f, 0x07, 0x71, # Caller src ip
  0xac, 0x1f, 0x0a, 0x1f, # Endpoint dst ip
  0xc8, 0xf2, 0x00, 0x50, # Proxy src port & dst port
  0x03, 0x00, 0x04, 0xe8, # CRC TLV start
  0xd6, 0x89, 0x2d, 0xea, # CRC TLV cont, VPCE id TLV start
  0x00, 0x17, 0x01, 0x76,
  0x70, 0x63, 0x65, 0x2d,
  0x30, 0x38, 0x64, 0x32,
  0x62, 0x66, 0x31, 0x35,
  0x66, 0x61, 0x63, 0x35,
  0x30, 0x30, 0x31, 0x63,
  0x39, 0x04, 0x00, 0x24, #VPCE id TLV end, NOOP TLV start
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, #NOOP TLV end
].pack("C*")

class PPv2Test <  Minitest::Test
  def new_pph(min_size=0)
    pph = ProxyProtocol.new(version: 2, protocol: :TCP4, source_addr: "127.0.0.1", dest_addr: "127.0.0.2", source_port: 5451, dest_port: 80)
    pph.add_tlv(0x80, "hey i'm a TLV!")
    pph.add_tlv(0x90, "is it me or are you just a TLV?")
    pph.add_tlv(0x91, "foo foo foo foo foo !!!")
    pph
  end
  
  def assert_http(url, pph, opt={}, &block)
    throw "url must start with /" unless url.match("^/")
    if opt[:ssl]
      ssl_ctx = OpenSSL::SSL::SSLContext.new
      ssl_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    resp = HTTP.get("#{opt[:ssl] ? "https://127.0.0.1:8092" : "http://127.0.0.1:8082"}#{url}", proxy_protocol_header: pph, ssl_context: ssl_ctx)
    type = opt[:type] || url.match("^/(.*)")[1].to_i(16) || url.match("^/(.*)")[1]
    if block_given?
      block.call(resp.body.to_s, type, pph)
    else
      assert_equal pph.tlv[type], resp.body.to_s
    end
  end
  
  def assert_http2(urls, pph, opt={}, &block)
    client = NetHttp2::Client.new(opt[:ssl] ? "https://127.0.0.1:8093" : "http://127.0.0.1:8083")
    client.proxy_protocol_header = pph
    urls = Array urls
    types = Array(opt[:type] || opt[:types])
    urls.each_with_index do |u, i|
      throw "url must start with /" unless u.match("^/")
      resp=client.call(:get, u)
      type = opt[:type] || u.match("^/(.*)")[1].to_i(16) || u.match("^/(.*)")[1]
      if block_given? then
        block.call(resp.body, type, pph)
      else
        assert_equal pph.tlv[type], resp.body
      end
    end
    client.close
  end
  
  def test_http
    assert_http "/0x80", new_pph
  end
  
  def test_http_ssl
    assert_http "/0x80", new_pph, ssl: true
  end
  
  def test_http2
    assert_http2 ['/0x91', '/0x80'], new_pph
  end
  
  def test_http2_ssl
    assert_http2 ['/0x91', '/0x80'], new_pph, ssl: true
  end
  
  def test_raw_aws_privatelink_header
    assert_http "/0xEA", RAW_PRIVATELINK_PP2_HEADER do |body, type, pph|
      assert_equal "\x01vpce-08d2bf15fac5001c9", body
    end
  end
  def test_AWS_VPCE_ID
    assert_http "/AWS_VPCE_ID", RAW_PRIVATELINK_PP2_HEADER do |body, type, pph|
      assert_equal "vpce-08d2bf15fac5001c9", body
    end
  end
  
end
