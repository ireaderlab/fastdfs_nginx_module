#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.c"

typedef struct {
    ngx_http_upstream_conf_t   upstream;
    ngx_uint_t                 headers_hash_max_size;
    ngx_uint_t                 headers_hash_bucket_size;
} ngx_http_fastdfs_loc_conf_t;

typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;


typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_hash_t                     hash;
} ngx_http_proxy_headers_t;


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *body_flushes;
    ngx_array_t                   *body_lengths;
    ngx_array_t                   *body_values;
    ngx_str_t                      body_source;

    ngx_http_proxy_headers_t       headers;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_headers_t       headers_cache;
#endif
    ngx_array_t                   *headers_source;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;

    ngx_http_complex_value_t      *method;
    ngx_str_t                      location;
    ngx_str_t                      url;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

    ngx_uint_t                     http_version;

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

#if (NGX_HTTP_SSL)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
    ngx_str_t                      ssl_certificate;
    ngx_str_t                      ssl_certificate_key;
    ngx_array_t                   *ssl_passwords;
#endif
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_http_status_t              status;
    ngx_http_chunked_t             chunked;
    ngx_http_proxy_vars_t          vars;
    off_t                          internal_body_length;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    unsigned                       head:1;
    unsigned                       internal_chunked:1;
    unsigned                       header_sent:1;
    char dest_ip_addr[IP_ADDRESS_SIZE];
} ngx_http_proxy_ctx_t;


static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http_proxy_copy_filter(ngx_event_pipe_t *p,
        ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p,
        ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_non_buffered_copy_filter(void *data,
        ssize_t bytes);
static ngx_int_t ngx_http_proxy_non_buffered_chunked_filter(void *data,
        ssize_t bytes);
static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc);
static int ngx_http_proxy_handler(ngx_http_request_t *r,
        const char *dest_ip_addr);

static char *ngx_http_fastdfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_fastdfs_process_init(ngx_cycle_t *cycle);
static void ngx_http_fastdfs_process_exit(ngx_cycle_t *cycle);

static void *ngx_http_fastdfs_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fastdfs_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);
static ngx_int_t ngx_http_fastdfs_handler(ngx_http_request_t *r);

static char  ngx_http_fastdfs_proxy_version[] = " HTTP/1.0"CRLF;


static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

/* Commands */
static ngx_command_t  ngx_http_fastdfs_commands[] = {
    { ngx_string("ngx_fastdfs_module"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_fastdfs_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_fastdfs_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_fastdfs_create_loc_conf,    /* create location configration */
    ngx_http_fastdfs_merge_loc_conf      /* merge location configration */
};

/* hook */
ngx_module_t  ngx_http_fastdfs_module = {
    NGX_MODULE_V1,
    &ngx_http_fastdfs_module_ctx,              /* module context */
    ngx_http_fastdfs_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_fastdfs_process_init,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_fastdfs_process_exit,             /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t fdfs_set_header(ngx_http_request_t *r, \
        const char *key, const char *low_key, const int key_len, \
        char *value, const int value_len)
{
    ngx_table_elt_t  *cc;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL)
    {
        return NGX_ERROR;
    }

    cc->hash = 1;
    cc->key.len = key_len;
    cc->key.data = (u_char *)key;
    cc->lowcase_key = (u_char *)low_key;
    cc->value.len = value_len;
    cc->value.data = (u_char *)value;

    return NGX_OK;
}

static ngx_int_t fdfs_set_content_disposition(ngx_http_request_t *r, \
        struct fdfs_http_response *pResponse)
{
    int value_len;
    value_len = snprintf(pResponse->content_disposition, \
            sizeof(pResponse->content_disposition), \
            "attachment; filename=\"%s\"", pResponse->attachment_filename);
    return fdfs_set_header(r, "Content-Disposition", "content-disposition",\
            sizeof("Content-Disposition") - 1, \
            pResponse->content_disposition, value_len);
}

static ngx_int_t fdfs_set_range(ngx_http_request_t *r, \
        struct fdfs_http_response *pResponse)
{
    return fdfs_set_header(r, "Range", "range", \
            sizeof("Range") - 1, pResponse->range, pResponse->range_len);
}

static ngx_int_t fdfs_set_content_range(ngx_http_request_t *r, \
        struct fdfs_http_response *pResponse)
{
    return fdfs_set_header(r, "Content-Range", "content-range", \
            sizeof("Content-Range") - 1, pResponse->content_range, \
            pResponse->content_range_len);
}

static ngx_int_t fdfs_set_accept_ranges(ngx_http_request_t *r)
{
    return fdfs_set_header(r, "Accept-Ranges", "accept-ranges", \
            sizeof("Accept-Ranges") - 1, "bytes", sizeof("bytes") - 1);
}

static ngx_int_t fdfs_set_location(ngx_http_request_t *r, \
        struct fdfs_http_response *pResponse)
{
    ngx_table_elt_t  *cc;

    cc = r->headers_out.location;
    if (cc == NULL)
    {
        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL)
        {
            return NGX_ERROR;
        }

        cc->hash = 1;
        cc->key.len = sizeof("Location") - 1;
        cc->key.data = (u_char *)"Location";
        cc->lowcase_key = (u_char *)"location";
    }

    cc->value.len = pResponse->redirect_url_len;
    cc->value.data = (u_char *)pResponse->redirect_url;

    return NGX_OK;
}

static void fdfs_output_headers(void *arg, struct fdfs_http_response *pResponse)
{
    ngx_http_request_t *r;
    ngx_int_t rc;

    if (pResponse->header_outputed)
    {
        return;
    }

    r = (ngx_http_request_t *)arg;

    if (pResponse->status != HTTP_OK \
            && pResponse->status != HTTP_PARTIAL_CONTENT)
    {
        if (pResponse->status == HTTP_MOVETEMP)
        {
            if (pResponse->range_len > 0)
            {
                fdfs_set_range(r, pResponse);
            }
            fdfs_set_location(r, pResponse);
        }
        else
        {
            return;  //does not send http header for other status
        }
    }
    else
    {
        if (pResponse->content_type != NULL)
        {
            r->headers_out.content_type.len = strlen(pResponse->content_type);
            r->headers_out.content_type.data = (u_char *)pResponse->content_type;
        }

        r->headers_out.content_length_n = pResponse->content_length;
        if (pResponse->attachment_filename != NULL)
        {
            fdfs_set_content_disposition(r, pResponse);
        }

        r->headers_out.last_modified_time = pResponse->last_modified;
        fdfs_set_accept_ranges(r);
        if (pResponse->content_range_len > 0)
        {
            fdfs_set_content_range(r, pResponse);
        }
    }

    ngx_http_set_content_type(r);

    r->headers_out.status = pResponse->status;
    pResponse->header_outputed = true;
    if (pResponse->content_length <= 0)
    {
        r->header_only = 1;
    }
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_send_header fail, return code=%d", rc);
        return;
    }
}

static int fdfs_send_reply_chunk(void *arg, const bool last_buf, \
        const char *buff, const int size)
{
    ngx_http_request_t *r;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_int_t rc;
    u_char *new_buff;

    r = (ngx_http_request_t *)arg;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_pcalloc fail");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    new_buff = ngx_palloc(r->pool, sizeof(u_char) * size);
    if (new_buff == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_palloc fail");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    memcpy(new_buff, buff, size);

    b->pos = (u_char *)new_buff;
    b->last = (u_char *)new_buff + size;
    b->memory = 1;
    b->last_in_chain = last_buf;
    b->last_buf = last_buf;

    /*
       ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
       "ngx_http_output_filter, sent: %d", r->connection->sent);
       */

    rc = ngx_http_output_filter(r, &out);
    if (rc == NGX_OK || rc == NGX_AGAIN)
    {
        return 0;
    }
    else
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_output_filter fail, return code: %d", rc);
        return rc;
    }
}

static int fdfs_send_file(void *arg, const char *filename, \
        const int filename_len, const int64_t file_offset, \
        const int64_t download_bytes)
{
    ngx_http_request_t *r;
    ngx_http_core_loc_conf_t *ccf;
    ngx_buf_t *b;
    ngx_str_t ngx_filename;
    ngx_open_file_info_t of;
    ngx_chain_t out;
    ngx_uint_t level;
    ngx_int_t rc;

    r = (ngx_http_request_t *)arg;

    ccf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_filename.data = (u_char *)filename;
    ngx_filename.len = filename_len;

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

#if defined(nginx_version) && (nginx_version >= 8018)
    of.read_ahead = ccf->read_ahead;
#endif
    of.directio = ccf->directio;
    of.valid = ccf->open_file_cache_valid;
    of.min_uses = ccf->open_file_cache_min_uses;
    of.errors = ccf->open_file_cache_errors;
    of.events = ccf->open_file_cache_events;
    if (ngx_open_cached_file(ccf->open_file_cache, &ngx_filename, \
                &of, r->pool) != NGX_OK)
    {
        switch (of.err)
        {
            case 0:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            case NGX_ENOENT:
            case NGX_ENOTDIR:
            case NGX_ENAMETOOLONG:
                level = NGX_LOG_ERR;
                rc = NGX_HTTP_NOT_FOUND;
                break;
            case NGX_EACCES:
                level = NGX_LOG_ERR;
                rc = NGX_HTTP_FORBIDDEN;
                break;
            default:
                level = NGX_LOG_CRIT;
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || ccf->log_not_found)
        {
            ngx_log_error(level, r->connection->log, of.err, \
                    "%s \"%s\" failed", of.failed, filename);
        }

        return rc;
    }

    if (!of.is_file)
    {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno, \
                "\"%s\" is not a regular file", filename);
        return NGX_HTTP_NOT_FOUND;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_pcalloc fail");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->file_pos = file_offset;
    b->file_last = file_offset + download_bytes;
    b->in_file = download_bytes > 0 ? 1 : 0;
    b->file->fd = of.fd;
    b->file->name.data = (u_char *)filename;
    b->file->name.len = filename_len;
    b->file->log = r->connection->log;
    b->file->directio = of.is_directio;

    b->last_in_chain = 1;
    b->last_buf = 1;

    rc = ngx_http_output_filter(r, &out);
    if (rc == NGX_OK || rc == NGX_AGAIN)
    {
        return NGX_HTTP_OK;
    }
    else
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_output_filter fail, return code: %d", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

static char *ngx_http_fastdfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, \
            ngx_http_core_module);

    fprintf(stderr, "ngx_http_fastdfs_set pid=%d\n", getpid());

    /* register hanlder */
    clcf->handler = ngx_http_fastdfs_handler;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_fastdfs_process_init(ngx_cycle_t *cycle)
{
    int result;

    fprintf(stderr, "ngx_http_fastdfs_process_init pid=%d\n", getpid());
    // do some init here
    if ((result=fdfs_mod_init()) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_http_fastdfs_process_exit(ngx_cycle_t *cycle)
{
    fprintf(stderr, "ngx_http_fastdfs_process_exit pid=%d\n", getpid());
    return;
}

static void *ngx_http_fastdfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fastdfs_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastdfs_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return conf;
}

static char * ngx_http_fastdfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_hash_init_t             hash;
    ngx_http_fastdfs_loc_conf_t *prev = parent;
    ngx_http_fastdfs_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
            prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
            prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
            prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
            prev->upstream.buffer_size,
            (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
            prev->upstream.next_upstream,
            (NGX_CONF_BITMASK_SET
             |NGX_HTTP_UPSTREAM_FT_ERROR
             |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
            |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    ngx_conf_merge_uint_value(conf->headers_hash_max_size,
            prev->headers_hash_max_size, 512);

    ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
            prev->headers_hash_bucket_size, 64);
    conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
            ngx_cacheline_size);

    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
                &prev->upstream, ngx_http_proxy_hide_headers, &hash)
            != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_fastdfs_handler(ngx_http_request_t *r)
{
    struct fdfs_http_context context;
    ngx_int_t rc;
    char url[4096];
    char *p;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN)
    {
        return rc;
    }

    if (r->uri.len + r->args.len + 1 >= sizeof(url))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "url too long, exceeds %d bytes!", (int)sizeof(url));
        return HTTP_BADREQUEST;
    }

    p = url;
    memcpy(p, r->uri.data, r->uri.len);
    p += r->uri.len;
    if (r->args.len > 0)
    {
        *p++ = '?';
        memcpy(p, r->args.data, r->args.len);
        p += r->args.len;
    }
    *p = '\0';

    memset(&context, 0, sizeof(context));
    context.arg = r;
    context.header_only = (r->method & NGX_HTTP_HEAD) ? 1 : 0;
    context.url = url;
    context.output_headers = fdfs_output_headers;
    context.send_file = fdfs_send_file;
    context.send_reply_chunk = fdfs_send_reply_chunk;
    context.proxy_handler = ngx_http_proxy_handler;
    context.server_port = ntohs(((struct sockaddr_in *)r->connection-> \
                local_sockaddr)->sin_port);

    if (r->headers_in.if_modified_since != NULL)
    {
        if (r->headers_in.if_modified_since->value.len < \
                sizeof(context.if_modified_since))
        {
            memcpy(context.if_modified_since, \
                    r->headers_in.if_modified_since->value.data, \
                    r->headers_in.if_modified_since->value.len);
        }

        /*
           ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
           "if_modified_since: %s", context.if_modified_since);
           */
    }

    if (r->headers_in.range != NULL)
    {
        char buff[64];
        if (r->headers_in.range->value.len >= sizeof(buff))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
                    "bad request, range length: %d exceeds buff " \
                    "size: %d, range: %*s", \
                    r->headers_in.range->value.len, \
                    (int)sizeof(buff), \
                    r->headers_in.range->value.len, \
                    r->headers_in.range->value.data);
            return NGX_HTTP_BAD_REQUEST;
        }

        memcpy(buff, r->headers_in.range->value.data, \
                r->headers_in.range->value.len);
        *(buff + r->headers_in.range->value.len) = '\0';
        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "buff=%s", buff);
        if (fdfs_parse_range(buff, &(context.range)) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
                    "bad request, invalid range: %s", buff);
            return NGX_HTTP_BAD_REQUEST;
        }
        context.if_range = true;

        /*
           ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
           "if_range=%d, start=%d, end=%d", context.if_range, \
           (int)context.range.start, (int)context.range.end);
           */
    }

    /*
       ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
       "args=%*s, uri=%*s", r->args.len, r->args.data, \
       r->uri.len, r->uri.data);
       */

    return fdfs_http_request_handler(&context);
}

    static int
ngx_http_proxy_handler(ngx_http_request_t *r, const char *dest_ip_addr)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_ctx_t        *ctx;
    ngx_http_proxy_loc_conf_t   *plcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_fastdfs_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_fastdfs_module);

    u = r->upstream;
    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL)
    {
        return NGX_ERROR;
    }

    ngx_str_set(&u->schema, "http://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_fastdfs_module;

    u->conf = &plcf->upstream;
    strcpy(ctx->dest_ip_addr, dest_ip_addr);
    u->resolved->host.data = (u_char *)ctx->dest_ip_addr;
    u->resolved->host.len = strlen(ctx->dest_ip_addr);
    u->resolved->port = (in_port_t)ntohs(((struct sockaddr_in *)r-> \
                connection->local_sockaddr)->sin_port);

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_status_line;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;
    r->state = 0;

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_copy_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_proxy_input_filter_init;
    u->input_filter = ngx_http_proxy_non_buffered_copy_filter;
    u->input_filter_ctx = r;

    u->accel = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%d", rc);
        return rc;
    }

    return NGX_DONE;
}


    static ngx_int_t
ngx_http_proxy_create_request(ngx_http_request_t *r)
{
#define FDFS_REDIRECT_PARAM  "redirect=1"

    size_t                        len;
    ngx_buf_t                    *b;
    ngx_uint_t                    i;
    ngx_chain_t                  *cl;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    char *p;
    char url[4096];
    char *the_url;
    size_t url_len;
    bool have_query;

    u = r->upstream;
    if (r->valid_unparsed_uri)
    {
        the_url = (char *)r->unparsed_uri.data;
        url_len = r->unparsed_uri.len;
        have_query = memchr(the_url, '?', url_len) != NULL;
    }
    else
    {
        if (r->uri.len + r->args.len + 1 >= sizeof(url))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "url too long, exceeds %d bytes!", (int)sizeof(url));
            return NGX_ERROR;
        }

        p = url;
        memcpy(p, r->uri.data, r->uri.len);
        p += r->uri.len;
        if (r->args.len > 0)
        {
            *p++ = '?';
            memcpy(p, r->args.data, r->args.len);
            p += r->args.len;
            have_query = true;
        }
        else
        {
            have_query = false;
        }

        the_url = url;
        url_len = p - url;
    }

    len = r->method_name.len + 1 + url_len + 1 +
        sizeof(FDFS_REDIRECT_PARAM) - 1 + 1 +
        sizeof(ngx_http_fastdfs_proxy_version) - 1 + sizeof(CRLF) - 1;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        len += header[i].key.len + 2 + header[i].value.len +
            sizeof(CRLF) - 1;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL)
    {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL)
    {
        return NGX_ERROR;
    }

    cl->buf = b;

    /* the request line */
    b->last = ngx_copy(b->last, r->method_name.data, r->method_name.len);
    *b->last++ = ' ';

    u->uri.data = b->last;
    b->last = ngx_cpymem(b->last, the_url, url_len);

    if (have_query)
    {
        *b->last++ = '&';
    }
    else
    {
        *b->last++ = '?';
    }
    b->last = ngx_cpymem(b->last, FDFS_REDIRECT_PARAM,
            sizeof(FDFS_REDIRECT_PARAM) - 1);

    u->uri.len =  b->last - u->uri.data;

    *b->last++ = ' ';
    b->last = ngx_cpymem(b->last, ngx_http_fastdfs_proxy_version,
            sizeof(ngx_http_fastdfs_proxy_version) - 1);

    part = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* void */; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        b->last = ngx_copy(b->last, header[i].key.data,
                header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';
        b->last = ngx_copy(b->last, header[i].value.data,
                header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

    /*
     *     fprintf(stderr, "http proxy header(%d, %d):\n\"%*s\"\n",
     *             len, b->last - b->pos, (b->last - b->pos), b->pos);
     *                 */

    u->request_bufs = cl;
    cl->next = NULL;

    return NGX_OK;
}


    static ngx_int_t
ngx_http_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;

    r->upstream->process_header = ngx_http_proxy_process_status_line;
    r->upstream->pipe->input_filter = ngx_http_proxy_copy_filter;
    r->upstream->input_filter = ngx_http_proxy_non_buffered_copy_filter;
    r->state = 0;

    return NGX_OK;
}

    static ngx_int_t
ngx_http_proxy_process_status_line(ngx_http_request_t *r)
{
    size_t                 len;
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            r->http_version = NGX_HTTP_VERSION_9;
            return NGX_OK;
        }

#endif

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "upstream sent no valid HTTP/1.0 header");

#if 0
        if (u->accel) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
#endif

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        u->headers_in.connection_close = 1;

        return NGX_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http proxy status %ui \"%V\"",
            u->headers_in.status_n, &u->headers_in.status_line);

    if (ctx->status.http_version < NGX_HTTP_VERSION_11) {
        u->headers_in.connection_close = 1;
    }

    u->process_header = ngx_http_proxy_process_header;

    return ngx_http_proxy_process_header(r);
}


    static ngx_int_t
ngx_http_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                    h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                    h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http proxy header: \"%V: %V\"",
                    &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http proxy header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            /* clear content length if response is chunked */

            u = r->upstream;

            if (u->headers_in.chunked) {
                u->headers_in.content_length_n = -1;
            }

            /*
             * set u->keepalive if response has no body; this allows to keep
             * connections alive in case of r->header_only or X-Accel-Redirect
             */

            ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

            if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
                    || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
                    || ctx->head
                    || (!u->headers_in.chunked
                        && u->headers_in.content_length_n == 0))
            {
                u->keepalive = !u->headers_in.connection_close;
            }

            if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS) {
                u->keepalive = 0;

                if (r->headers_in.upgrade) {
                    u->upgrade = 1;
                }
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* there was error while a header line parsing */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


    static ngx_int_t
ngx_http_proxy_input_filter_init(void *data)
{
    ngx_http_request_t    *r = data;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http proxy filter init s:%ui h:%d c:%d l:%O",
            u->headers_in.status_n, ctx->head, u->headers_in.chunked,
            u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
            || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
            || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else if (u->headers_in.chunked) {
        /* chunked */

        u->pipe->input_filter = ngx_http_proxy_chunked_filter;
        u->pipe->length = 3; /* "0" LF LF */

        u->input_filter = ngx_http_proxy_non_buffered_chunked_filter;
        u->length = 1;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    return NGX_OK;
}


    static ngx_int_t
ngx_http_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t           *b;
    ngx_chain_t         *cl;
    ngx_http_request_t  *r;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    cl = ngx_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NGX_OK;
    }

    p->length -= b->last - b->pos;

    if (p->length == 0) {
        r = p->input_ctx;
        p->upstream_done = 1;
        r->upstream->keepalive = !r->upstream->headers_in.connection_close;

    } else if (p->length < 0) {
        r = p->input_ctx;
        p->upstream_done = 1;

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "upstream sent more data than specified in "
                "\"Content-Length\" header");
    }

    return NGX_OK;
}


    static ngx_int_t
ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_int_t              rc;
    ngx_buf_t             *b, **prev;
    ngx_chain_t           *cl;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *ctx;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    b = NULL;
    prev = &buf->shadow;

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);

        if (rc == NGX_OK) {

            /* a chunk has been parsed successfully */

            cl = ngx_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->pos = buf->pos;
            b->start = buf->start;
            b->end = buf->end;
            b->tag = p->tag;
            b->temporary = 1;
            b->recycled = 1;

            *prev = b;
            prev = &b->shadow;

            if (p->in) {
                *p->last_in = cl;
            } else {
                p->in = cl;
            }
            p->last_in = &cl->next;

            /* STUB */ b->num = buf->num;

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                    "input buf #%d %p", b->num, b->pos);

            if (buf->last - buf->pos >= ctx->chunked.size) {

                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

                continue;
            }

            ctx->chunked.size -= buf->last - buf->pos;
            buf->pos = buf->last;
            b->last = buf->last;

            continue;
        }

        if (rc == NGX_DONE) {

            /* a whole response has been parsed successfully */

            p->upstream_done = 1;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            break;
        }

        if (rc == NGX_AGAIN) {

            /* set p->length, minimal amount of data we want to see */

            p->length = ctx->chunked.length;

            break;
        }

        /* invalid response */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "upstream sent invalid chunked response");

        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http proxy chunked state %ui, length %O",
            ctx->chunked.state, p->length);

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                "input buf %p %z", b->pos, b->last - b->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


    static ngx_int_t
ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


    static ngx_int_t
ngx_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_int_t              rc;
    ngx_buf_t             *b, *buf;
    ngx_chain_t           *cl, **ll;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);

        if (rc == NGX_OK) {

            /* a chunk has been parsed successfully */

            cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;

            b->flush = 1;
            b->memory = 1;

            b->pos = buf->pos;
            b->tag = u->output.tag;

            if (buf->last - buf->pos >= ctx->chunked.size) {
                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

            } else {
                ctx->chunked.size -= buf->last - buf->pos;
                buf->pos = buf->last;
                b->last = buf->last;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http proxy out buf %p %z",
                    b->pos, b->last - b->pos);

            continue;
        }

        if (rc == NGX_DONE) {

            /* a whole response has been parsed successfully */

            u->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            break;
        }

        if (rc == NGX_AGAIN) {
            break;
        }

        /* invalid response */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "upstream sent invalid chunked response");

        return NGX_ERROR;
    }

    /* provide continuous buffer for subrequests in memory */

    if (r->subrequest_in_memory) {

        cl = u->out_bufs;

        if (cl) {
            buf->pos = cl->buf->pos;
        }

        buf->last = buf->pos;

        for (cl = u->out_bufs; cl; cl = cl->next) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http proxy in memory %p-%p %O",
                    cl->buf->pos, cl->buf->last, ngx_buf_size(cl->buf));

            if (buf->last == cl->buf->pos) {
                buf->last = cl->buf->last;
                continue;
            }

            buf->last = ngx_movemem(buf->last, cl->buf->pos,
                    cl->buf->last - cl->buf->pos);

            cl->buf->pos = buf->last - (cl->buf->last - cl->buf->pos);
            cl->buf->last = buf->last;
        }
    }

    return NGX_OK;
}


    static void
ngx_http_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "abort http proxy request");

    return;
}


    static void
ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "finalize http proxy request");
    return;
}
