#include <ngx_http_redirectionio_module.h>

static void ngx_str_copy(ngx_str_t *src, ngx_str_t *dest);

static ngx_int_t ngx_http_redirectionio_send_uint8(ngx_connection_t *c, uint8_t uint8);

static ngx_int_t ngx_http_redirectionio_send_uint16(ngx_connection_t *c, uint16_t uint16);

static ngx_int_t ngx_http_redirectionio_send_uint32(ngx_connection_t *c, uint32_t uint32);

static ngx_int_t ngx_http_redirectionio_send_string(ngx_connection_t *c, const char *string, size_t buf_size);

static ngx_int_t ngx_http_redirectionio_send_protocol_header(ngx_connection_t *c, ngx_str_t *project_key, uint16_t command);

ngx_int_t ngx_http_redirectionio_protocol_send_match(ngx_connection_t *c, ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx, ngx_str_t *project_key) {
    ngx_int_t                           rv;
    ngx_table_elt_t                     *h;
    ngx_list_part_t                     *part;
    struct REDIRECTIONIO_HeaderMap      *first_header = NULL, *current_header = NULL;
    const char                          *request_serialized;
    char                                *method, *uri, *host = NULL, *scheme = NULL, *client_ip;
    ngx_uint_t                          i;
    ngx_http_redirectionio_conf_t       *conf;
    ngx_http_redirectionio_header_set_t *hs;
    ngx_str_t                           hsn, hsv;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    // Create header map
    // First add request headers
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
        current_header->name = ngx_http_redirectionio_str_to_char(&h[i].key, r->pool);
        current_header->value = ngx_http_redirectionio_str_to_char(&h[i].value, r->pool);
        current_header->next = first_header;

        first_header = current_header;
    }

    // Then set headers
    hs = conf->headers_set.elts;

    for (i = 0; i < conf->headers_set.nelts ; i++) {
        if (ngx_http_complex_value(r, hs[i].name, &hsn) != NGX_OK) {
            continue;
        }

        if (ngx_http_complex_value(r, hs[i].value, &hsv) != NGX_OK) {
            continue;
        }

        current_header = (struct REDIRECTIONIO_HeaderMap *)ngx_pcalloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));
        current_header->name = ngx_http_redirectionio_str_to_char(&hsn, r->pool);
        current_header->value = ngx_http_redirectionio_str_to_char(&hsv, r->pool);
        current_header->next = first_header;

        first_header = current_header;
    }

    if (ctx->scheme.len > 0) {
        scheme = ngx_http_redirectionio_str_to_char(&ctx->scheme, r->pool);
    } else {
        scheme = "http";
    }

#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        scheme = "https";
    }
#endif

    uri = ngx_http_redirectionio_str_to_char(&r->unparsed_uri, r->pool);
    method = ngx_http_redirectionio_str_to_char(&r->method_name, r->pool);

    if (ctx->host.len > 0) {
        host = ngx_http_redirectionio_str_to_char(&ctx->host, r->pool);
    } else if (r->headers_in.host != NULL) {
        host = ngx_http_redirectionio_str_to_char(&r->headers_in.host->value, r->pool);
    }

    // Create redirection io request
    ctx->request = (struct REDIRECTIONIO_Request *)redirectionio_request_create(uri, host, scheme, method, first_header);

    if (ctx->request == NULL) {
        return NGX_ERROR;
    }

    client_ip = ngx_http_redirectionio_str_to_char(&r->connection->addr_text, r->pool);
    redirectionio_request_set_remote_addr(ctx->request, (const char *)client_ip, conf->trusted_proxies);

    // Serialize request
    request_serialized = redirectionio_request_json_serialize(ctx->request);

    if (request_serialized == NULL) {
        return NGX_ERROR;
    }

    // Send protocol header
    rv = ngx_http_redirectionio_send_protocol_header(c, project_key, REDIRECTIONIO_PROTOCOL_COMMAND_MATCH_ACTION);

    if (rv == NGX_AGAIN) {
        return rv;
    }

    if (rv != NGX_OK) {
        ctx->connection_error = 1;

        return NGX_ERROR;
    }

    // Send serialized request length
    rv = ngx_http_redirectionio_send_uint32(c, strlen(request_serialized));

    if (rv != NGX_OK) {
        ctx->connection_error = 1;

        return NGX_ERROR;
    }

    // Send serialized request
    rv = ngx_http_redirectionio_send_string(c, request_serialized, strlen(request_serialized));

    free((void *)request_serialized);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending request: %d", rv);
        ctx->connection_error = 1;

        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_redirectionio_log_t *log) {
    ssize_t     wlen = strlen(log->log_serialized);
    ngx_int_t   rv;

    // Send protocol header
    rv = ngx_http_redirectionio_send_protocol_header(c, &log->project_key, REDIRECTIONIO_PROTOCOL_COMMAND_LOG);

    if (rv == NGX_AGAIN) {
        return rv;
    }

    if (rv != NGX_OK) {
        return NGX_ERROR;
    }

    // Send log length
    rv = ngx_http_redirectionio_send_uint32(c, wlen);

    if (rv != NGX_OK) {
        return NGX_ERROR;
    }

    rv = ngx_http_redirectionio_send_string(c, log->log_serialized, wlen);

    if (rv != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_http_redirectionio_log_t* ngx_http_redirectionio_protocol_create_log(ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx, ngx_str_t *project_key) {
    const char                      *client_ip, *log_serialized;
    ngx_http_redirectionio_log_t    *log;

    client_ip = ngx_http_redirectionio_str_to_char(&r->connection->addr_text, r->pool);
    log_serialized = redirectionio_api_create_log_in_json(ctx->request, r->headers_out.status, ctx->response_headers, ctx->action, PROXY_VERSION_STR(PROXY_VERSION), r->start_msec, client_ip);

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

    if (rv == NGX_AGAIN) {
        return rv;
    }

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending protocol major version: %d", rv);

        return rv;
    }

    // Send protocol minor version
    rv = ngx_http_redirectionio_send_uint8(c, REDIRECTIONIO_PROTOCOL_VERSION_MINOR);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending protocol minor version: %d", rv);

        return rv;
    }

    // Send project key length
    rv = ngx_http_redirectionio_send_uint8(c, (unsigned char)project_key->len);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending project key length: %d", rv);

        return rv;
    }

    rv = ngx_http_redirectionio_send_string(c, (const char *)project_key->data, project_key->len);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending project key: %d", rv);

        return rv;
    }

    rv = ngx_http_redirectionio_send_uint16(c, command);

    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "[redirectionio] error sending command: %d", rv);

        return rv;
    }

    return NGX_OK;
}
