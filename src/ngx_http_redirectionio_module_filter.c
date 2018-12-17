#include <ngx_http_redirectionio_module.h>

static void ngx_http_redirectionio_write_filter_headers_handler(ngx_event_t *wev);
static void ngx_http_redirectionio_finalize_request(ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx);

void ngx_http_redirectionio_read_filter_headers_handler(ngx_event_t *rev, cJSON *json) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_http_request_t              *r;
    ngx_connection_t                *c;
    cJSON                           *headers, *item, *name, *value;
    ngx_table_elt_t                 *h;
    ngx_list_part_t                 *part;

    c = rev->data;
    r = c->data;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;
    ctx->headers_filtered = 1;
    ctx->wait_for_header_filtering = 0;

    if (json == NULL) {
        ngx_http_redirectionio_finalize_request(r, ctx);

        return;
    }

    headers = cJSON_GetObjectItem(json, "headers");

    if (headers == NULL || headers->type != cJSON_Array) {
        ngx_http_redirectionio_finalize_request(r, ctx);

        return;
    }

    // Deactivate all old headers
    part = &r->headers_out.headers.part;
    h = part->elts;

    for (u_int i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        h[i].hash = 0;
        h[i].value.len = 0;
    }

    // Reinit list of headers
    ngx_list_init(&r->headers_out.headers, r->headers_out.headers.pool, cJSON_GetArraySize(headers), sizeof(ngx_table_elt_t));
    item = headers->child;

    while (item != NULL) {
        // Item is a header
        name = cJSON_GetObjectItem(item, "name");
        value = cJSON_GetObjectItem(item, "value");
        item = item->next;

        if (name == NULL || value == NULL || name->type != cJSON_String || value->type != cJSON_String) {
            continue;
        }

        h = ngx_list_push(&r->headers_out.headers);

        if (h == NULL) {
            continue;
        }

        h->hash = 1;
        h->key.data = (u_char *)name->valuestring;
        h->key.len = strlen(name->valuestring);

        h->value.data = (u_char *)value->valuestring;
        h->value.len = strlen(value->valuestring);
    }

    ngx_http_redirectionio_release_resource(conf->connection_pool, ctx->resource, 0);
    ctx->wait_for_connection = 0;
    ctx->resource = NULL;

    ngx_http_redirectionio_finalize_request(r, ctx);
}

ngx_int_t ngx_http_redirectionio_match_on_response_status_header_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    // Skip if no need to redirect
    if (ctx == NULL || ctx->status == 0 || ctx->match_on_response_status == 0 || ctx->is_redirected) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    if (r->headers_out.status != ctx->match_on_response_status) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    if (ctx->status != 410) {
        // Set target
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);

        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = ctx->target.len;
        r->headers_out.location->value.data = ctx->target.data;
    }

    r->headers_out.status = ctx->status;
    // Avoid loop if we redirect on the same status as we match
    ctx->is_redirected = 1;

    return ngx_http_special_response_handler(r, ctx->status);
}

ngx_int_t ngx_http_redirectionio_headers_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_int_t                       status;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    // Skip if no need to filters headers (no context, no rule, no filter on headers, or already filtered headers)
    if (ctx == NULL || ctx->status == 0 || ctx->should_filter_headers == 0 || ctx->headers_filtered) {
        return ngx_http_next_header_filter(r);
    }

    // Get connection
    if (ctx->resource == NULL) {
        if (ctx->wait_for_connection) {
            return NGX_AGAIN;
        }

        // @TODO Use another pool available function that
        status = ngx_reslist_acquire(conf->connection_pool, ngx_http_redirectionio_pool_available, r);

        if (status == NGX_AGAIN) {
            ctx->wait_for_connection = 1;

            return status;
        }

        if (status != NGX_OK) {
            return ngx_http_next_header_filter(r);
        }
    }

    // Check connection
    if (ctx->connection_error) {
        ngx_http_redirectionio_release_resource(conf->connection_pool, ctx->resource, 1);

        ctx->wait_for_connection = 0;
        ctx->resource = NULL;
        ctx->connection_error = 0;

        return ngx_http_next_header_filter(r);
    }

    if (ctx->wait_for_header_filtering) {
        return NGX_AGAIN;
    }

    ngx_http_redirectionio_write_filter_headers_handler(ctx->resource->peer.connection->write);
    ctx->wait_for_header_filtering = 1;

    return NGX_AGAIN;
}

ngx_int_t ngx_http_redirectionio_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_int_t                       status;
    ngx_chain_t                     *buf;
    ngx_str_t                       buffer_str;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx->body_buffer) {
        buf = ctx->body_buffer;

        while (buf->next != NULL) {
            buf = buf->next;
        }

        buf->next = in;

        in = ctx->body_buffer;
    }

    // Skip if no need to filters body and headers (no context, no rule)
    if (ctx == NULL || ctx->status == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    // Check if we are waiting for filtering headers or connection
    if (ctx->wait_for_header_filtering || ctx->wait_for_connection) {
        // Set request is buffered to avoid its destruction by nginx
        r->buffered = 1;
        ctx->body_buffer = in;

        return NGX_AGAIN;
    }

    // Skip if no need to filters body (no filter on body, or already filtered headers)
    if (ctx->should_filter_body == 0 || ctx->body_filtered) {
        return ngx_http_next_body_filter(r, in);
    }

    // @TODO Otherwise stream the body to redirection io agent

    // Get connection

    // Stream body

    return ngx_http_next_body_filter(r, in);
}

static void ngx_http_redirectionio_write_filter_headers_handler(ngx_event_t *wev) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_redirectionio_conf_t   *conf;

    c = wev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    ngx_add_timer(c->read, RIO_TIMEOUT);
    ctx->read_handler = ngx_http_redirectionio_read_filter_headers_handler;

    ngx_http_redirectionio_protocol_send_filter_header(c, r, &conf->project_key, &ctx->matched_rule_id);
}

static void ngx_http_redirectionio_finalize_request(ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx) {
    // @TODO Check for errors
    // Send headers
    ngx_http_next_header_filter(r);

    // Send body if already available
    if (ctx->body_buffer != NULL) {
        ngx_http_redirectionio_body_filter(r, NULL);
    }

    r->buffered = 0;

    ngx_http_finalize_request(r, NGX_OK);
}
