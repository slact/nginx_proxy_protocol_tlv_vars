# nginx_proxy_protocol_tlv_vars

Add support for [Proxy Protocol](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) v2 TLV parsing to variables for `http` and `stream` modules.

Nginx released PPv2 support in version 1.15.2, however, they kept TLV parsing limited to the nonfree [Nginx Plus](https://www.nginx.com/blog/nginx-plus-r16-released/#r16-ppv2-privatelink) package. This patch brings that stuff for open source Nginx users.

## Applying Patch

```bash
VERSION=1.16.0 #nginx version to patch
#grab nginx
wget http://nginx.org/download/nginx-$VERSION.tar.gz
cd nginx-$VERSION/
wget https://github.com/slact/nginx_proxy_protocol_tlv_vars/raw/master/nginx-$VERSION-proxy_protocol_vars.patch
patch -p1 < nginx-$VERSION-proxy_protocol_vars.patch

#now build nginx as you normally would
./configure ...
make
make install
```

## Usage

This patch adds the following variables when using `listen proxy_protocol`:

#### `$proxy_protocol_tlv_0xXX`
  the TLV value with type code `0xXX`, where `XX` is a 2-digit hex value.
  ```nginx
  add_header X-pp-tlv-0xEC $proxy_protocol_tlv_0xEC;
  ```
  

#### `$proxy_protocol_tlv_AWS_VPCE_ID`
  Amazon's AWS [VPC Endpoint ID](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#custom-tlv). This is the equivalent of [Nginx Plus](https://www.nginx.com/blog/nginx-plus-r16-released/#r16-ppv2-privatelink)' `$proxy_protocol_tlv_0xEA`.
  ```nginx
  add_header X-aws-vpce-id $proxy_protocol_tlv_AWS_VPCE_ID; #vpce-08d2bf15fac5001c9
  ```
  
## Caveats

- When using SSL, Nginx limits the length of the entire Proxy Protocol header message to 108 bytes. Larger headers will be dropped. Although this limit is trivial to increase, I have chosen not to do so out of performance considerations. 

- Unlike Nginx Plus, this patch does not parse Amazon's VPC Endpoint ID into `$proxy_protocol_tlv_0xEA`, but uses `$proxy_protocol_tlv_AWS_VPCE_ID` instead. `$proxy_protocol_tlv_0xEA` retains its initial raw value, which Amazon made `"\0x01<vpce_id>"` for some reason.

- As described in the [Proxy Protocol](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) spec, the `0x04` (No-op) TLV type is ignored.

## TODO

 - `PP2_TYPE_CRC32C` support
