#include <ngx_http_redirectionio_module.h>

static void ngx_str_copy(ngx_str_t *src, ngx_str_t *dest);

static char* ngx_str_to_char(ngx_str_t *src, ngx_pool_t *pool);

static ngx_int_t ngx_http_redirectionio_send_uint8(ngx_connection_t *c, uint8_t uint8);

static ngx_int_t ngx_http_redirectionio_send_uint16(ngx_connection_t *c, uint16_t uint16);

static ngx_int_t ngx_http_redirectionio_send_uint32(ngx_connection_t *c, uint32_t uint32);

static ngx_int_t ngx_http_redirectionio_send_string(ngx_connection_t *c, const char *string, size_t buf_size);

static ngx_int_t ngx_http_redirectionio_send_protocol_header(ngx_connection_t *c, ngx_str_t *project_key, uint16_t command);

static void ngx_http_redirectionio_request_cleanup(void *request);

void ngx_http_redirectionio_protocol_send_match(ngx_connection_t *c, ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx, ngx_str_t *project_key) {
    ngx_int_t                       rv;
    ngx_table_elt_t                 *h;
    ngx_list_part_t                 *part;
    struct REDIRECTIONIO_HeaderMap  *first_header = NULL, *current_header = NULL;
    const char                      *request_serialized;
    char                            *method, *uri, *host = NULL, *scheme = "http";
    ngx_uint_t                      i;
    ngx_pool_cleanup_t              *cln;

    // Create header map
    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].value.len <= 0 || h[i].key.len <= 0) {
            continue;
        }

        current_header = (struct REDIRECTIONIO_HeaderMap *)ngx_pcalloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));
        current_header->name = ngx_str_to_char(&h[i].key, r->pool);
        current_header->value = ngx_str_to_char(&h[i].value, r->pool);
        current_header->next = first_header;

        first_header = current_header;
    }

    #if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        scheme = "https";
    }
    #endif

    uri = ngx_str_to_char(&r->unparsed_uri, r->pool);
    method = ngx_str_to_char(&r->method_name, r->pool);

    if (r->headers_in.host != NULL) {
        host = ngx_str_to_char(&r->headers_in.host->value, r->pool);
    }

    // Create redirection io request
    ctx->request = (struct REDIRECTIONIO_Request *)redirectionio_request_create(uri, host, scheme, method, first_header);

    if (ctx->request == NULL) {
        return;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        redirectionio_request_drop(ctx->request);
        ctx->request = NULL;

        return;
    }

    cln->data = ctx->request;
    cln->handler = ngx_http_redirectionio_request_cleanup;

    // Serialize request
    request_serialized = redirectionio_request_json_serialize(ctx->request);

    if (request_serialized == NULL) {
        return;
    }

    // Send protocol header
    rv = ngx_http_redirectionio_send_protocol_header(c, project_key, REDIRECTIONIO_PROTOCOL_COMMAND_MATCH_ACTION);

    if (rv != NGX_OK) {
        ctx->connection_error = 1;

        return;
    }

    // Send serialized request length
    rv = ngx_http_redirectionio_send_uint32(c, strlen(request_serialized));

    if (rv != NGX_OK) {
        ctx->connection_error = 1;

        return;
    }

    // Send serialized request
    rv = ngx_http_redirectionio_send_string(c, request_serialized, strlen(request_serialized));

    free((void *)request_serialized);

    if (rv != NGX_OK) {
        ctx->connection_error = 1;

        return;
    }
}

ngx_int_t ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_redirectionio_log_t *log) {
    ssize_t     wlen = strlen(log->log_serialized);
    ngx_int_t   rv;

    // Send protocol header
    rv = ngx_http_redirectionio_send_protocol_header(c, &log->project_key, REDIRECTIONIO_PROTOCOL_COMMAND_LOG);

    if (rv != NGX_OK) {
        return rv;
    }

    // Send log length
    rv = ngx_http_redirectionio_send_uint32(c, wlen);

    if (rv != NGX_OK) {
        return rv;
    }

    return ngx_http_redirectionio_send_string(c, log->log_serialized, wlen);
}

ngx_http_redirectionio_log_t* ngx_http_redirectionio_protocol_create_log(ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx, ngx_str_t *project_key) {
    const char                      *log_serialized;
    ngx_http_redirectionio_log_t    *log;

    log_serialized = redirectionio_api_create_log_in_json(ctx->request, r->headers_out.status, ctx->response_headers, ctx->action, PROXY_VERSION_STR(PROXY_VERSION), r->start_msec);

    if (log_serialized == NULL) {
        return NULL;
    }

    log = malloc(sizeof(ngx_http_redirectionio_log_t));

    ngx_memzero(log, sizeof(ngx_http_redirectionio_log_t));

    if (log == NULL) {
        return NULL;
    }

    ngx_str_copy(project_key, &log->project_key);
    log->log_serialized = log_serialized;

    return log;
}

void ngx_http_redirectionio_protocol_free_log(ngx_http_redirectionio_log_t *log) {
    free(log->project_key.data);
    free((char *)log->log_serialized);

    free(log);
}

static void ngx_str_copy(ngx_str_t *src, ngx_str_t *dest) {
    dest->len = src->len;
    dest->data = malloc(dest->len);
    ngx_memcpy(dest->data, src->data, dest->len);
}

static char* ngx_str_to_char(ngx_str_t *src, ngx_pool_t *pool) {
    char *str;

    str = (char *)ngx_pcalloc(pool, src->len + 1);
    ngx_memcpy(str, src->data, src->len);
    *((char *)str + src->len) = '\0';

    return str;
}

static ngx_int_t ngx_http_redirectionio_send_uint8(ngx_connection_t *c, uint8_t uint8) {
    ssize_t     slen;

    slen = ngx_send(c, (u_char *)&uint8, sizeof(uint8_t));

    if (slen <= 0) {
        return slen;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_send_uint16(ngx_connection_t *c, uint16_t uint16) {
    ssize_t  srlen = sizeof(uint16_t);
    ssize_t  serlen = sizeof(uint16_t);
    ssize_t  sdrlen = 0;

    uint16 = htons(uint16);

    while (sdrlen < serlen) {
        srlen = ngx_send(c, (u_char *)&uint16, srlen);

        if (srlen <= 0) {
            return srlen;
        }

        sdrlen += srlen;
        srlen = serlen - sdrlen;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_send_uint32(ngx_connection_t *c, uint32_t uint32) {
    size_t  srlen = sizeof(uint32_t);
    size_t  serlen = sizeof(uint32_t);
    size_t  sdrlen = 0;

    uint32 = htonl(uint32);

    while (sdrlen < serlen) {
        srlen = ngx_send(c, (u_char *)&uint32, srlen);

        if (srlen <= 0) {
            return srlen;
        }

        sdrlen += srlen;
        srlen = serlen - sdrlen;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_send_string(ngx_connection_t *c, const char *string, size_t buf_size) {
    size_t  srlen = buf_size;
    size_t  sdrlen = 0;

    while (sdrlen < buf_size) {
        srlen = ngx_send(c, (u_char *)(string + sdrlen), srlen);

        if (srlen <= 0) {
            return srlen;
        }

        sdrlen += srlen;
        srlen = buf_size - sdrlen;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_send_protocol_header(ngx_connection_t *c, ngx_str_t *project_key, uint16_t command) {
    ngx_int_t   rv;

    if (project_key->len > 255) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] size of token cannot exceed 255 characters");

        return NGX_ERROR;
    }

    // Send protocol major version
    rv = ngx_http_redirectionio_send_uint8(c, REDIRECTIONIO_PROTOCOL_VERSION_MAJOR);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending protocol major version");

        return rv;
    }

    // Send protocol minor version
    rv = ngx_http_redirectionio_send_uint8(c, REDIRECTIONIO_PROTOCOL_VERSION_MINOR);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending protocol minor version");

        return rv;
    }

    // Send project key length
    rv = ngx_http_redirectionio_send_uint8(c, (unsigned char)project_key->len);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending project key length");

        return rv;
    }

    rv = ngx_http_redirectionio_send_string(c, (const char *)project_key->data, project_key->len);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending project key");

        return rv;
    }

    rv = ngx_http_redirectionio_send_uint16(c, command);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending command");

        return rv;
    }

    return NGX_OK;
}

static void ngx_http_redirectionio_request_cleanup(void *request) {
    redirectionio_request_drop(request);
}
