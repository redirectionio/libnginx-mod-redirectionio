#include <ngx_http_redirectionio_protocol.h>
#include <ngx_http_redirectionio_module.h>

const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%V\", \"request_uri\": \"%V\", \"host\": \"%V\", \"rule_id\": \"%V\", \"target\": \"%V\", \"status_code\": %d, \"user_agent\": \"%V\", \"referer\": \"%V\", \"method\": \"%V\", \"proxy\": \"%s\" }";

static void ngx_str_copy(ngx_str_t *src, ngx_str_t *dest);

static char* ngx_str_to_char(ngx_str_t *src, ngx_pool_t *pool);

static ngx_table_elt_t* ngx_http_redirectionio_find_header(u_char *key, ngx_list_part_t *part);

static ngx_int_t ngx_http_redirectionio_send_uint8(ngx_connection_t *c, uint8_t uint8);

static ngx_int_t ngx_http_redirectionio_send_uint16(ngx_connection_t *c, uint16_t uint16);

static ngx_int_t ngx_http_redirectionio_send_uint32(ngx_connection_t *c, uint32_t uint32);

static ngx_int_t ngx_http_redirectionio_send_string(ngx_connection_t *c, const char *string, size_t buf_size);

static ngx_int_t ngx_http_redirectionio_send_protocol_header(ngx_connection_t *c, ngx_str_t *project_key, uint16_t command);

static void ngx_http_redirectionio_request_cleanup(void *request);

void ngx_http_redirectionio_protocol_send_match(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key) {
    ngx_int_t                       rv;
    ngx_table_elt_t                 *h;
    ngx_list_part_t                 *part;
    struct REDIRECTIONIO_HeaderMap  *first_header = NULL, *current_header = NULL;
    struct REDIRECTIONIO_Request    *redirectionio_request;
    const char                      *request_serialized;
    char                            *method, *uri;
    ngx_uint_t                      i;
    ngx_pool_cleanup_t              *cln;

    // Create header map
    part = &r->headers_out.headers.part;
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

        // Not used skip it
        if (h[i].hash == 0 || h[i].value.len <= 0 || h[i].key.len <= 0) {
            continue;
        }

        current_header = (struct REDIRECTIONIO_HeaderMap *)ngx_pcalloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));
        current_header->name = ngx_str_to_char(&h[i].key, r->pool);
        current_header->value = ngx_str_to_char(&h[i].value, r->pool);
        current_header->next = first_header;

        first_header = current_header;
    }

    uri = ngx_str_to_char(&r->unparsed_uri, r->pool);
    method = ngx_str_to_char(&r->method_name, r->pool);

    // Create redirection io request
    redirectionio_request = (struct REDIRECTIONIO_Request *)redirectionio_request_create(uri, method, first_header);

    if (redirectionio_request == NULL) {
        return;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        redirectionio_request_drop(redirectionio_request);

        return;
    }

    cln->data = redirectionio_request;
    cln->handler = ngx_http_redirectionio_request_cleanup;

    // Serialize request
    request_serialized = redirectionio_request_json_serialize(redirectionio_request);

    if (request_serialized == NULL) {
        return;
    }

    // Send protocol header
    rv = ngx_http_redirectionio_send_protocol_header(c, project_key, REDIRECTIONIO_PROTOCOL_COMMAND_MATCH_ACTION);

    if (rv != NGX_OK) {
        return;
    }

    // Send serialized request length
    rv = ngx_http_redirectionio_send_uint32(c, strlen(request_serialized));

    if (rv != NGX_OK) {
        return;
    }

    // Send serialized request
    rv = ngx_http_redirectionio_send_string(c, request_serialized, strlen(request_serialized));

    free((void *)request_serialized);

    if (rv != NGX_OK) {
        return;
    }
}

void ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_redirectionio_log_t *log) {
    ssize_t     wlen;
    u_char      *dst;
    ngx_str_t   v;
    ngx_int_t   rv;

    wlen =
        sizeof(COMMAND_LOG_QUERY)
        + log->project_key.len
        + log->uri.len
        + log->host.len
        + log->rule_id.len
        + 3 // Status code length
        + log->location.len
        + log->user_agent.len
        + log->referer.len
        + log->method.len
        + strlen(PROXY_VERSION_STR(PROXY_VERSION))
        - 20 // 10 * 2 (%x) characters replaced with values
    ;

    dst = (u_char *) ngx_pcalloc(c->pool, wlen);

    ngx_sprintf(
        dst,
        COMMAND_LOG_QUERY,
        &log->project_key,
        &log->uri,
        &log->host,
        &log->rule_id,
        &log->location,
        log->status,
        &log->user_agent,
        &log->referer,
        &log->method,
        PROXY_VERSION_STR(PROXY_VERSION)
    );

    v = (ngx_str_t) { wlen, dst };

    // Send protocol header
    rv = ngx_http_redirectionio_send_protocol_header(c, &log->project_key, REDIRECTIONIO_PROTOCOL_COMMAND_LOG);

    if (rv != NGX_OK) {
        return;
    }

    // Send log length
    rv = ngx_http_redirectionio_send_uint32(c, v.len);

    if (rv != NGX_OK) {
        return;
    }

    rv = ngx_http_redirectionio_send_string(c, (const char *)v.data, v.len);

    if (rv != NGX_OK) {
        return;
    }
}

ngx_http_redirectionio_log_t* ngx_http_redirectionio_protocol_create_log(ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id) {
    // @TODO Replace log structure by directly the query string

    ngx_table_elt_t                 *header_location;
    ngx_http_redirectionio_log_t    *log = malloc(sizeof(ngx_http_redirectionio_log_t));
    ngx_memzero(log, sizeof(ngx_http_redirectionio_log_t));

    if (log == NULL) {
        return NULL;
    }

    ngx_str_copy(project_key, &log->project_key);
//    ngx_str_copy(rule_id, &log->rule_id);
    ngx_str_copy(&r->unparsed_uri, &log->uri);

    log->user_agent = (ngx_str_t)ngx_null_string;
    log->referer = (ngx_str_t)ngx_null_string;
    log->host = (ngx_str_t)ngx_null_string;
    log->location = (ngx_str_t)ngx_null_string;
    log->status = r->headers_out.status;

    if (r->headers_in.user_agent != NULL) {
        ngx_str_copy(&r->headers_in.user_agent->value, &log->user_agent);
    }

    if (r->headers_in.referer != NULL) {
        ngx_str_copy(&r->headers_in.referer->value, &log->referer);
    }

    if (r->headers_in.host != NULL) {
        ngx_str_copy(&r->headers_in.host->value, &log->host);
    }

    header_location = ngx_http_redirectionio_find_header((u_char *)"location", &r->headers_out.headers.part);

    if (header_location != NULL) {
        ngx_str_copy(&header_location->value, &log->location);
    }

    ngx_str_copy(&r->method_name, &log->method);

    return log;
}

void ngx_http_redirectionio_protocol_free_log(ngx_http_redirectionio_log_t *log) {
    free(log->project_key.data);
    free(log->rule_id.data);
    free(log->uri.data);
    free(log->user_agent.data);
    free(log->referer.data);
    free(log->host.data);
    free(log->location.data);
    free(log->method.data);

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

static ngx_table_elt_t* ngx_http_redirectionio_find_header(u_char *key, ngx_list_part_t *part) {
    ngx_uint_t          i;
    ngx_table_elt_t     *h;

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

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len > 0 && ngx_strncasecmp(key, h[i].key.data, h[i].key.len) == 0) {
            return &h[i];
        }
    }

    return NULL;
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
