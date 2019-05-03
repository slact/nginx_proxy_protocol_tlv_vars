#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'

require 'minitest'
require 'minitest/reporters'
require "minitest/autorun"

require "http"
require "http/2"
require "digest/crc32c"
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
  def new_pph(tlvs={}, opt={})
    if opt[:ipv6]
      prot = :TCP6
      src = "fe80::ca60:ff:fe05:0123"
      dst = "fe80::ca60:ff:fe05:abcd"
      default_tlvs = {
        0x80 => "hi!",
        0x90 => "oh?",
        0x91 => "smol"
      }
    else
      prot = :TCP4
      src = "192.168.0.100"
      dst = "192.168.0.200"
      default_tlvs = {
        0x80 => "hey i'm a TLV!",
        0x90 => "is it me or are you just a TLV?",
        0x91 => "foo foo foo !!!"
      }
    end
    
    pph = ProxyProtocol.new(version: 2, protocol: prot, source_addr: src, dest_addr: dst, source_port: 5451, dest_port: 80)
    if tlvs.length == 0
      tlvs = default_tlvs
    end
    tlvs.each do |k, v|
      pph.add_tlv k, v
    end
    pph
  end
  
  def assert_all_transports(url, pph, opt = {})
    assert_http url, pph, opt
    assert_http url, pph, opt.merge(ssl: true)
    assert_http2 url, pph, opt
    assert_http2 url, pph, opt.merge(ssl: true)
  end
  
  def assert_http(url, pph, opt={}, &block)
    throw "url must start with /" unless url.match("^/")
    if opt[:ssl]
      ssl_ctx = OpenSSL::SSL::SSLContext.new
      ssl_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    resp = HTTP.get("#{opt[:ssl] ? "https://127.0.0.1:8092" : "http://127.0.0.1:8082"}#{url}", proxy_protocol_header: pph, ssl_context: ssl_ctx)
    type = opt[:type] || url.match("^/(.*)")[1].to_i(16) || url.match("^/(.*)")[1]
    assert_equal 200, resp.code, "bad response code"
    if block_given?
      block.call(resp.body.to_s, type, pph)
    else
      if opt[:body]
        assert_equal opt[:body].to_s, resp.body.to_s
      else
        assert !pph.tlv[type].nil?
        assert_equal pph.tlv[type], resp.body.to_s
      end
    end
  end
  
  def assert_http2(urls, pph, opt={}, &block)
    client = HTTP2Client.new(opt[:ssl] ? "https://127.0.0.1:8093" : "http://127.0.0.1:8083", proxy_protocol_header: pph)
    urls = Array urls
    types = Array(opt[:type] || opt[:types])
    urls.each_with_index do |u, i|
      throw "url must start with /" unless u.match("^/")
      resp = client.get u
      type = types[i] || u.match("^/(.*)")[1].to_i(16) || u.match("^/(.*)")[1]
      assert_equal 200, resp.status, "bad response code"
      if block_given? then
        block.call(resp.body, type, pph)
      else
        if opt[:body]
          assert_equal opt[:body].to_s, resp.body
        else
          assert !pph.tlv[type].nil?
          assert_equal pph.tlv[type], resp.body
        end
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
    assert_http "/0xEA", RAW_PRIVATELINK_PP2_HEADER, body: "\x01vpce-08d2bf15fac5001c9"
  end
  def test_AWS_VPCE_ID
    assert_http "/AWS_VPCE_ID", RAW_PRIVATELINK_PP2_HEADER, body: "vpce-08d2bf15fac5001c9"
  end
  
  def test_bad_AWS_VPCE_ID
    pph = new_pph({0xEA => ""})
    assert_http "/AWS_VPCE_ID", pph, body: ""
    
    pph = new_pph({0xEA => "foobar"})
    assert_http "/AWS_VPCE_ID", pph , body: ""
  end
  
  def test_named_tlvs
    pph = new_pph({
      0x30 => "NETNS-value",
      0x02 => "AUTHORITY-value",
      0x01 => "ALPN-value"
    })
    assert_http "/ALPN", pph, type: 0x01
    assert_http "/AUTHORITY", pph, type: 0x02
    assert_http "/NETNS", pph, type: 0x30
  end
  
  def test_unknown_tlv_name
    assert_http "/NO_SUCH_TLV", new_pph, body: ""
  end
  
  def test_raw_crc32c_gen
    pph = RAW_PRIVATELINK_PP2_HEADER.dup
    assert_equal 0x03, pph[28].ord
    assert_equal 0x00, pph[29].ord
    assert_equal 0x04, pph[30].ord
    stored_crc = pph[31..34]
    pph[31..34]="\0\0\0\0"
    assert_equal RAW_PRIVATELINK_PP2_HEADER.length, pph.length
    
    crc = [Digest::CRC32c.checksum(pph)].pack("N")
    assert_equal stored_crc, crc
  end
  
  def test_good_checksum
    pph = new_pph
    pph.checksum
    assert_http "/CRC32C", pph, type: 0x03
    
    #checksum in the middle
    pph = new_pph({ 0x12 =>"...okay..."})
    pph.checksum
    pph.add_tlv 0xEC, "apples"
    pph.add_tlv 0x01, "wotm8"
    assert_http "/CRC32C", pph, type: 0x03
  end
  
  def test_proxy_protocol_builtin_vars
    pph = new_pph
    assert_all_transports "/proxy_protocol_port", pph, body: pph.source_port
    assert_all_transports "/proxy_protocol_addr", pph, body: pph.source_addr
  end
  
  def test_ppv2_ipv6
    pph = new_pph({}, ipv6: true)
    assert_all_transports "/proxy_protocol_port", pph, body: pph.source_port
    assert_all_transports "/proxy_protocol_addr", pph, body: pph.source_addr
    assert_all_transports "/0x80", pph
  end
  
  def test_bad_checksum
    pph = new_pph
    pph.bad_checksum!
    assert_all_transports "/0x80", pph, body: ""
    assert_all_transports "/proxy_protocol_port", pph, body: ""
    assert_all_transports "/proxy_protocol_addr", pph, body: ""
    
    pph = new_pph({}, ipv6: true)
    pph.bad_checksum!
    assert_all_transports "/0x80", pph, body: ""
    assert_all_transports "/proxy_protocol_port", pph, body: ""
    assert_all_transports "/proxy_protocol_addr", pph, body: ""
  end
end
