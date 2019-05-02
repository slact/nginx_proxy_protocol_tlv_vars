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
      assert_equal resp.body.to_s, pph.tlv[type]
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
        assert_equal resp.body, pph.tlv[type]
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
end
