
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PROXY_PROTOCOL_MAX_HEADER  107


typedef struct {
  uint8_t               type;
  ngx_str_t             val;
} ngx_proxy_protocol_tlv_t;


struct ngx_proxy_protocol_s {
    ngx_str_t                src_addr;
    ngx_str_t                dst_addr;
    in_port_t                src_port;
    in_port_t                dst_port;
    ngx_proxy_protocol_tlv_t *proxy_protocol_tlvs;
};


u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
    u_char *last);
ngx_int_t ngx_proxy_protocol_variable_tlv(ngx_connection_t *c, ngx_str_t *varname, ngx_str_t *varval);



#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
