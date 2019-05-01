
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>


#define NGX_PROXY_PROTOCOL_AF_INET          1
#define NGX_PROXY_PROTOCOL_AF_INET6         2


#define ngx_proxy_protocol_parse_uint16(p)  ((p)[0] << 8 | (p)[1])


typedef struct {
    u_char                                  signature[12];
    u_char                                  version_command;
    u_char                                  family_transport;
    u_char                                  len[2];
} ngx_proxy_protocol_header_t;


typedef struct {
    u_char                                  src_addr[4];
    u_char                                  dst_addr[4];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} ngx_proxy_protocol_inet_addrs_t;


typedef struct {
    u_char                                  src_addr[16];
    u_char                                  dst_addr[16];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} ngx_proxy_protocol_inet6_addrs_t;


static u_char *ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf,
    u_char *last);


u_char *
ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    size_t     len;
    u_char     ch, *p, *addr, *port;
    ngx_int_t  n;

    static const u_char signature[] = "\r\n\r\n\0\r\nQUIT\n";

    p = buf;
    len = last - buf;

    if (len >= sizeof(ngx_proxy_protocol_header_t)
        && memcmp(p, signature, sizeof(signature) - 1) == 0)
    {
        return ngx_proxy_protocol_v2_read(c, buf, last);
    }

    if (len < 8 || ngx_strncmp(p, "PROXY ", 6) != 0) {
        goto invalid;
    }

    p += 6;
    len -= 6;

    if (len >= 7 && ngx_strncmp(p, "UNKNOWN", 7) == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol unknown protocol");
        p += 7;
        goto skip;
    }

    if (len < 5 || ngx_strncmp(p, "TCP", 3) != 0
        || (p[3] != '4' && p[3] != '6') || p[4] != ' ')
    {
        goto invalid;
    }

    p += 5;
    addr = p;

    for ( ;; ) {
        if (p == last) {
            goto invalid;
        }

        ch = *p++;

        if (ch == ' ') {
            break;
        }

        if (ch != ':' && ch != '.'
            && (ch < 'a' || ch > 'f')
            && (ch < 'A' || ch > 'F')
            && (ch < '0' || ch > '9'))
        {
            goto invalid;
        }
    }

    len = p - addr - 1;
    c->proxy_protocol_addr.data = ngx_pnalloc(c->pool, len);

    if (c->proxy_protocol_addr.data == NULL) {
        return NULL;
    }

    ngx_memcpy(c->proxy_protocol_addr.data, addr, len);
    c->proxy_protocol_addr.len = len;

    for ( ;; ) {
        if (p == last) {
            goto invalid;
        }

        if (*p++ == ' ') {
            break;
        }
    }

    port = p;

    for ( ;; ) {
        if (p == last) {
            goto invalid;
        }

        if (*p++ == ' ') {
            break;
        }
    }

    len = p - port - 1;

    n = ngx_atoi(port, len);

    if (n < 0 || n > 65535) {
        goto invalid;
    }

    c->proxy_protocol_port = (in_port_t) n;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol address: %V %d", &c->proxy_protocol_addr,
                   c->proxy_protocol_port);

skip:

    for ( /* void */ ; p < last - 1; p++) {
        if (p[0] == CR && p[1] == LF) {
            return p + 2;
        }
    }

invalid:

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "broken header: \"%*s\"", (size_t) (last - buf), buf);

    return NULL;
}


u_char *
ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last)
{
    ngx_uint_t  port, lport;

    if (last - buf < NGX_PROXY_PROTOCOL_MAX_HEADER) {
        return NULL;
    }

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NULL;
    }

    switch (c->sockaddr->sa_family) {

    case AF_INET:
        buf = ngx_cpymem(buf, "PROXY TCP4 ", sizeof("PROXY TCP4 ") - 1);
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        buf = ngx_cpymem(buf, "PROXY TCP6 ", sizeof("PROXY TCP6 ") - 1);
        break;
#endif

    default:
        return ngx_cpymem(buf, "PROXY UNKNOWN" CRLF,
                          sizeof("PROXY UNKNOWN" CRLF) - 1);
    }

    buf += ngx_sock_ntop(c->sockaddr, c->socklen, buf, last - buf, 0);

    *buf++ = ' ';

    buf += ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf, last - buf,
                         0);

    port = ngx_inet_get_port(c->sockaddr);
    lport = ngx_inet_get_port(c->local_sockaddr);

    return ngx_slprintf(buf, last, " %ui %ui" CRLF, port, lport);
}

static ngx_int_t
ngx_proxy_protocol_v2_next_tlv(u_char **curptr, u_char *last, 
    ngx_proxy_protocol_tlv_t *tlv)
{
    uint8_t type;
    uint16_t len;
    u_char *cur = *curptr;
    if(cur == last) {
        //no more TLVs
        return NGX_DONE;
    }
    if(cur+3 > last) {
        return NGX_ERROR;
    }
    type = *cur;
    cur++;
    len = ngx_proxy_protocol_parse_uint16(cur);
    cur+=2;
    if(cur+len > last) {
        return NGX_ERROR;
    }
    tlv->type = type;
    tlv->val.len = len;
    tlv->val.data = cur;
    *curptr = cur+len;
    return NGX_OK;
}

static ngx_int_t
ngx_proxy_protocol_v2_read_tlv(ngx_connection_t *c, u_char *buf, u_char *last)
{
    size_t                    total_data_sz = 0;
    int                       tlv_count = 0;
    ngx_int_t                 rc;
    u_char                   *cur = buf;
    ngx_proxy_protocol_tlv_t  tlv;
    while((rc = ngx_proxy_protocol_v2_next_tlv(&cur, last, &tlv)) == NGX_OK) {
        tlv_count++;
        total_data_sz += tlv.val.len;
    }
    if(rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "invalid PROXY protocol v2 TLV vector");
        return NGX_ERROR;
    }
    if(tlv_count == 0) {
        //no TLVs
        assert(c->proxy_protocol_tlv == NULL);
        return NGX_OK;
    }
    ngx_proxy_protocol_tlv_t  *tlvs;
    if((tlvs = ngx_palloc(c->pool, sizeof(*tlvs)*(tlv_count+1))) == NULL) {
        return NGX_ERROR;
    }
    u_char *valbuf = NULL;
    if(total_data_sz > 0 && (valbuf = ngx_palloc(c->pool, total_data_sz)) == NULL) {
        return NGX_ERROR;
    }
    
    //set the TLVs
    int i=0;
    while((rc = ngx_proxy_protocol_v2_next_tlv(&cur, last, &tlvs[i])) == NGX_OK) {
        ngx_memcpy(valbuf, tlvs[i].val.data, tlvs[i].val.len);
        tlvs[i].val.data = valbuf;
        valbuf += tlvs[i].val.len;
        i++;
    }
    //last TLV is all-zeroes to mark the end of the array
    tlvs[i].val.data = NULL;
    tlvs[i].val.len = 0;
    tlvs[i].type = 0;
    c->proxy_protocol_tlv = tlvs;
    
    return NGX_OK;
}

ngx_int_t
ngx_proxy_protocol_variable_tlv(ngx_connection_t *c, ngx_str_t *varname,
    ngx_str_t *varval)
{
    ngx_str_t                   var;
    ngx_int_t                   tlv_type;
    ngx_proxy_protocol_tlv_t   *cur;
    
    if(!c->proxy_protocol_tlv) {
        //no TLVs at all
        return NGX_DECLINED;
    }
    
    var = *varname;
    var.data += sizeof("proxy_protocol_tlv_") - 1;
    var.len -= sizeof("proxy_protocol_tlv_") - 1;
    
    //check TLVs of the form "0xXX"
    
    //check for "0x"
    if (var.len < 2 || var.len > 4 || 
        var.data[0] != '0' || var.data[1] != 'x')
    {
        return NGX_ERROR;
    }
    
    if ((tlv_type = ngx_hextoi(&var.data[2], var.len-2)) == NGX_ERROR) {
        return NGX_ERROR;
    }

    for(cur = c->proxy_protocol_tlv; !(cur->val.len == 0 && cur->type == 0); cur++) {
        if(cur->type == tlv_type) {
            *varval = cur->val;
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

static u_char *
ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    u_char                             *end;
    size_t                              len;
    socklen_t                           socklen;
    ngx_uint_t                          version, command, family, transport;
    ngx_sockaddr_t                      sockaddr;
    ngx_proxy_protocol_header_t        *header;
    ngx_proxy_protocol_inet_addrs_t    *in;
#if (NGX_HAVE_INET6)
    ngx_proxy_protocol_inet6_addrs_t   *in6;
#endif

    header = (ngx_proxy_protocol_header_t *) buf;

    buf += sizeof(ngx_proxy_protocol_header_t);

    version = header->version_command >> 4;

    if (version != 2) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "unknown PROXY protocol version: %ui", version);
        return NULL;
    }

    len = ngx_proxy_protocol_parse_uint16(header->len);

    if ((size_t) (last - buf) < len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "header is too large");
        return NULL;
    }

    end = buf + len;

    command = header->version_command & 0x0f;

    /* only PROXY is supported */
    if (command != 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported command %ui", command);
        return end;
    }

    transport = header->family_transport & 0x0f;

    /* only STREAM is supported */
    if (transport != 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported transport %ui",
                       transport);
        return end;
    }

    family = header->family_transport >> 4;

    switch (family) {

    case NGX_PROXY_PROTOCOL_AF_INET:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet_addrs_t)) {
            return NULL;
        }

        in = (ngx_proxy_protocol_inet_addrs_t *) buf;

        sockaddr.sockaddr_in.sin_family = AF_INET;
        sockaddr.sockaddr_in.sin_port = 0;
        memcpy(&sockaddr.sockaddr_in.sin_addr, in->src_addr, 4);

        c->proxy_protocol_port = ngx_proxy_protocol_parse_uint16(in->src_port);

        socklen = sizeof(struct sockaddr_in);

        buf += sizeof(ngx_proxy_protocol_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)

    case NGX_PROXY_PROTOCOL_AF_INET6:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet6_addrs_t)) {
            return NULL;
        }

        in6 = (ngx_proxy_protocol_inet6_addrs_t *) buf;

        sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        sockaddr.sockaddr_in6.sin6_port = 0;
        memcpy(&sockaddr.sockaddr_in6.sin6_addr, in6->src_addr, 16);

        c->proxy_protocol_port = ngx_proxy_protocol_parse_uint16(in6->src_port);

        socklen = sizeof(struct sockaddr_in6);

        buf += sizeof(ngx_proxy_protocol_inet6_addrs_t);

        break;

#endif

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported address family %ui",
                       family);
        return end;
    }

    c->proxy_protocol_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (c->proxy_protocol_addr.data == NULL) {
        return NULL;
    }

    c->proxy_protocol_addr.len = ngx_sock_ntop(&sockaddr.sockaddr, socklen,
                                               c->proxy_protocol_addr.data,
                                               NGX_SOCKADDR_STRLEN, 0);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 address: %V %d", &c->proxy_protocol_addr,
                   c->proxy_protocol_port);

    if (buf < end) {
      
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 %z bytes of tlv", end - buf);
        ngx_proxy_protocol_v2_read_tlv(c, buf, end);
    }

    return end;
}
