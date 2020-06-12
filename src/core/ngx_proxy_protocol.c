
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


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

// CRC32c
// pycrc --algorithm=table-driven --model=crc-32c --std=ANSI --symbol-prefix=ngx_ppv2_crc32c_ --generate=h
typedef unsigned long int ngx_ppv2_crc32c_t;
#define ngx_ppv2_crc32c_init()      (0xffffffff)
#define ngx_ppv2_crc32c_finalize(crc)      (crc ^ 0xffffffff)
// pycrc --algorithm=table-driven --model=crc-32c --std=ANSI --symbol-prefix=ngx_ppv2_crc32c_ --generate=c
static const ngx_ppv2_crc32c_t crc_table[256] = {
    0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
    0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
    0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
    0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
    0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
    0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
    0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
    0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a, 0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
    0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
    0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
    0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
    0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
    0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
    0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
    0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
    0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
    0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c, 0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
    0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
    0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
    0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c, 0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
    0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
    0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
    0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d, 0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
    0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
    0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
    0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
    0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
    0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
    0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee, 0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
    0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
    0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
    0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e, 0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
};
static ngx_ppv2_crc32c_t ngx_ppv2_crc32c_update(ngx_ppv2_crc32c_t crc, const void *data, size_t data_len)
{
    const unsigned char *d = (const unsigned char *)data;
    unsigned int tbl_idx;

    while (data_len--) {
        tbl_idx = (crc ^ *d) & 0xff;
        crc = (crc_table[tbl_idx] ^ (crc >> 8)) & 0xffffffff;

        d++;
    }
    return crc & 0xffffffff;
}

static ngx_int_t ngx_ppv2_tlv_parse_aws_vpce_id(ngx_connection_t *c, ngx_str_t *in, ngx_str_t *out);
static ngx_int_t ngx_ppv2_tlv_passthrough(ngx_connection_t *c, ngx_str_t *in, ngx_str_t *out);

typedef struct {
    ngx_str_t                               name;
    u_char                                  type;
    ngx_int_t (*handler)(ngx_connection_t *c, ngx_str_t *value_in, ngx_str_t *value_out);
} ngx_proxy_protocol_tlv_named_handler_t;

static ngx_proxy_protocol_tlv_named_handler_t ngx_proxy_protocol_tlv_named_handler[] = {
    { ngx_string("aws_vpce_id"), 0xEA, ngx_ppv2_tlv_parse_aws_vpce_id},
    { ngx_string("alpn"),        0x01, ngx_ppv2_tlv_passthrough},
    { ngx_string("authority"),   0x02, ngx_ppv2_tlv_passthrough},
    { ngx_string("crc32c"),      0x03, ngx_ppv2_tlv_passthrough},
    { ngx_string("netns"),       0x30, ngx_ppv2_tlv_passthrough},
    { ngx_null_string,           0x00, NULL}
};

static u_char *ngx_proxy_protocol_tlv_value_sentinel = (u_char *)"END";


static u_char *ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p,
    u_char *last, ngx_str_t *addr);
static u_char *ngx_proxy_protocol_read_port(u_char *p, u_char *last,
    in_port_t *port, u_char sep);
static u_char *ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf,
    u_char *last);


u_char *
ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    size_t                 len;
    u_char                *p;
    ngx_proxy_protocol_t  *pp;

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

    pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    p = ngx_proxy_protocol_read_addr(c, p, last, &pp->src_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_addr(c, p, last, &pp->dst_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_port(p, last, &pp->src_port, ' ');
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_port(p, last, &pp->dst_port, CR);
    if (p == NULL) {
        goto invalid;
    }

    if (p == last) {
        goto invalid;
    }

    if (*p++ != LF) {
        goto invalid;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    c->proxy_protocol = pp;

    return p;

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


static u_char *
ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p, u_char *last,
    ngx_str_t *addr)
{
    size_t  len;
    u_char  ch, *pos;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
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
            return NULL;
        }
    }

    len = p - pos - 1;

    addr->data = ngx_pnalloc(c->pool, len);
    if (addr->data == NULL) {
        return NULL;
    }

    ngx_memcpy(addr->data, pos, len);
    addr->len = len;

    return p;
}


static u_char *
ngx_proxy_protocol_read_port(u_char *p, u_char *last, in_port_t *port,
    u_char sep)
{
    size_t      len;
    u_char     *pos;
    ngx_int_t   n;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
        }

        if (*p++ == sep) {
            break;
        }
    }

    len = p - pos - 1;

    n = ngx_atoi(pos, len);
    if (n < 0 || n > 65535) {
        return NULL;
    }

    *port = (in_port_t) n;

    return p;
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

static ngx_int_t ngx_proxy_protocol_v2_checksum(u_char *start, u_char *end, ngx_proxy_protocol_tlv_t *tlv) {
    uint32_t                            saved_crc;
    ngx_ppv2_crc32c_t                   given_crc, crc;

    // CRC32C Must be 4 bytes to be valid
    if (tlv->val.len != sizeof(uint32_t)) {
        return NGX_ERROR;
    }

    ngx_memcpy(&saved_crc, tlv->val.data, sizeof(uint32_t));
    given_crc = ntohl(saved_crc);

    ngx_memzero(tlv->val.data, sizeof(uint32_t));

    crc = ngx_ppv2_crc32c_update(ngx_ppv2_crc32c_init(), (void *)start, end - start);
    crc = ngx_ppv2_crc32c_finalize(crc);

    ngx_memcpy(tlv->val.data, &saved_crc, sizeof(uint32_t));

    if(given_crc != crc) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_proxy_protocol_v2_read_tlv(ngx_connection_t *c, u_char *buf, u_char *first, u_char *last, ngx_proxy_protocol_t *pp)
{
    size_t                    total_data_sz = 0;
    int                       tlv_count = 0;
    ngx_int_t                 rc;
    u_char                   *cur = buf;
    
    ngx_proxy_protocol_tlv_t  tlv;
    while((rc = ngx_proxy_protocol_v2_next_tlv(&cur, last, &tlv)) == NGX_OK) {
        switch(tlv.type) {
            case 0x04: //no-op
                //skip it
                break;
            case 0x03: //CRC32c
                if (ngx_proxy_protocol_v2_checksum(first, last, &tlv) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                   "bad PROXY protocol v2 checksum");
                    //clear $proxy_protocol_port
                    pp->src_port = 0;
                    //clear $proxy_protocol_server_port
                    pp->dst_port = 0;
                    //clear $proxy_protocol_addr
                    pp->src_addr.len = 0;
                    pp->src_addr.data = NULL;
                    //clear $proxy_protocol_server_addr
                    pp->dst_addr.len = 0;
                    pp->dst_addr.data = NULL;
                    return NGX_ERROR;
                }
                /* fall through */
            default:
                tlv_count++;
                total_data_sz += tlv.val.len;
                break;
        }
    }
    if(rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "invalid PROXY protocol v2 TLV vector");
        return NGX_ERROR;
    }
    if(tlv_count == 0) {
        //no TLVs
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
    cur = buf;
    while((rc = ngx_proxy_protocol_v2_next_tlv(&cur, last, &tlvs[i])) == NGX_OK) {
        if(tlvs[i].type != 0x04) { //not NO-OP
            ngx_memcpy(valbuf, tlvs[i].val.data, tlvs[i].val.len);
            tlvs[i].val.data = valbuf;
            valbuf += tlvs[i].val.len;
            i++;
        }
    }
    //last TLV is a sentinel to mark the end of the array
    tlvs[i].val.data = ngx_proxy_protocol_tlv_value_sentinel;
    tlvs[i].val.len = 0;
    tlvs[i].type = 0;
    pp->proxy_protocol_tlvs = tlvs;
    
    return NGX_OK;
}

static ngx_proxy_protocol_tlv_t *
ngx_proxy_protocol_find_tlv_type(ngx_connection_t *c, u_char type) {
    ngx_proxy_protocol_tlv_t   *cur;
    for(cur = c->proxy_protocol->proxy_protocol_tlvs; cur->val.data != ngx_proxy_protocol_tlv_value_sentinel; cur++) {
        if(cur->type == type) {
            return cur;
        }
    }
    return NULL;
}

static ngx_int_t ngx_proxy_protocol_tlv_match_named_variable(ngx_connection_t *c, ngx_str_t *var, ngx_str_t *varval) {
    ngx_proxy_protocol_tlv_named_handler_t *cur;
    ngx_proxy_protocol_tlv_t *tlv;
    for(cur = ngx_proxy_protocol_tlv_named_handler; cur->name.data != NULL; cur++) {
        if (var->len == cur->name.len
            && ngx_memcmp(var->data, cur->name.data, var->len) == 0)
        {
            if((tlv = ngx_proxy_protocol_find_tlv_type(c, cur->type)) == NULL) {
                //we didn't see this TLV type in the PPv2 header
                return NGX_DECLINED;
            }
            return cur->handler(c, &tlv->val, varval);
        }
    }
    //no such variable
    return NGX_DECLINED;
}

ngx_int_t
ngx_proxy_protocol_variable_tlv(ngx_connection_t *c, ngx_str_t *varname,
    ngx_str_t *varval)
{
    ngx_str_t                   var;
    ngx_int_t                   tlv_type;
    ngx_proxy_protocol_tlv_t   *tlv;

    if(!c->proxy_protocol || !c->proxy_protocol->proxy_protocol_tlvs) {
        //no TLVs at all
        return NGX_DECLINED;
    }

    var = *varname;
    var.data += sizeof("proxy_protocol_tlv_") - 1;
    var.len -= sizeof("proxy_protocol_tlv_") - 1;
    //check for "0x"
    if (var.len == 4 && var.data[0] == '0' && var.data[1] == 'x') {
        //check TLVs of the form "0xXX"
        if ((tlv_type = ngx_hextoi(&var.data[2], var.len-2)) == NGX_ERROR) {
            return NGX_ERROR;
        }
        if ((tlv = ngx_proxy_protocol_find_tlv_type(c, tlv_type)) != NULL) {
            *varval = tlv->val;
            return NGX_OK;
        }
        //not found
        return NGX_DECLINED;
    }
    return ngx_proxy_protocol_tlv_match_named_variable(c, &var, varval);
}

static ngx_int_t ngx_ppv2_tlv_parse_aws_vpce_id(ngx_connection_t *c, ngx_str_t *in, ngx_str_t *out) {
    //https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol
    if(in->len == 0 || in->data[0] != 0x01) {
        //an unecpected first byte to be sure, and an unwelcome one
        return NGX_DECLINED;
    }
    //strip off the PP2_SUBTYPE_AWS_VPCE_ID byte
    out->len = in->len-1;
    out->data = in->data+1;
    return NGX_OK;
}

static ngx_int_t ngx_ppv2_tlv_passthrough(ngx_connection_t *c, ngx_str_t *in, ngx_str_t *out) {
    *out = *in;
    return NGX_OK;
}

static u_char *
ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    u_char                             *start = buf;
    u_char                             *end;
    size_t                              len;
    socklen_t                           socklen;
    ngx_uint_t                          version, command, family, transport;
    ngx_sockaddr_t                      src_sockaddr, dst_sockaddr;
    ngx_proxy_protocol_t               *pp;
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

    pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    family = header->family_transport >> 4;

    switch (family) {

    case NGX_PROXY_PROTOCOL_AF_INET:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet_addrs_t)) {
            return NULL;
        }

        in = (ngx_proxy_protocol_inet_addrs_t *) buf;

        src_sockaddr.sockaddr_in.sin_family = AF_INET;
        src_sockaddr.sockaddr_in.sin_port = 0;
        memcpy(&src_sockaddr.sockaddr_in.sin_addr, in->src_addr, 4);

        dst_sockaddr.sockaddr_in.sin_family = AF_INET;
        dst_sockaddr.sockaddr_in.sin_port = 0;
        memcpy(&dst_sockaddr.sockaddr_in.sin_addr, in->dst_addr, 4);

        pp->src_port = ngx_proxy_protocol_parse_uint16(in->src_port);
        pp->dst_port = ngx_proxy_protocol_parse_uint16(in->dst_port);

        socklen = sizeof(struct sockaddr_in);

        buf += sizeof(ngx_proxy_protocol_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)

    case NGX_PROXY_PROTOCOL_AF_INET6:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet6_addrs_t)) {
            return NULL;
        }

        in6 = (ngx_proxy_protocol_inet6_addrs_t *) buf;

        src_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        src_sockaddr.sockaddr_in6.sin6_port = 0;
        memcpy(&src_sockaddr.sockaddr_in6.sin6_addr, in6->src_addr, 16);

        dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        dst_sockaddr.sockaddr_in6.sin6_port = 0;
        memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, in6->dst_addr, 16);

        pp->src_port = ngx_proxy_protocol_parse_uint16(in6->src_port);
        pp->dst_port = ngx_proxy_protocol_parse_uint16(in6->dst_port);

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

    pp->src_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (pp->src_addr.data == NULL) {
        return NULL;
    }

    pp->src_addr.len = ngx_sock_ntop(&src_sockaddr.sockaddr, socklen,
                                     pp->src_addr.data, NGX_SOCKADDR_STRLEN, 0);

    pp->dst_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (pp->dst_addr.data == NULL) {
        return NULL;
    }

    pp->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, socklen,
                                     pp->dst_addr.data, NGX_SOCKADDR_STRLEN, 0);

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    if (buf < end) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 %z bytes of tlv", end - buf);
        ngx_proxy_protocol_v2_read_tlv(c, buf, start, end, pp);
    }

    c->proxy_protocol = pp;

    return end;
}
