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


class PubSubTest <  Minitest::Test
  def test_foo
    pph = ProxyProtocol.new(version: 2, protocol: :TCP4, source_addr: "127.0.0.1", dest_addr: "127.0.0.2", source_port: 5451, dest_port: 80)
    pph.add_tlv(0x80, "hey i'm a TLV!")
    pph.add_tlv(0x90, "is it me or are you just a TLV?")
    pph.add_tlv(0x91, "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo !!!")
    resp = HTTP.get("http://127.0.0.1:8082/", proxy_protocol_header: pph)
    puts resp
  end
end
