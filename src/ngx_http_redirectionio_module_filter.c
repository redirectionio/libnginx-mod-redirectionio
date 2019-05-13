#include <ngx_http_redirectionio_module.h>

ngx_int_t ngx_http_redirectionio_match_on_response_status_header_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    const char                      *redirect;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    if (ctx->matched_rule == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    if (ctx->is_redirected) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    redirect = redirectionio_get_redirect(ctx->matched_rule_str, (const char *)r->unparsed_uri.data, r->headers_out.status);

    if (redirect == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    cJSON *redirect_json = cJSON_Parse(redirect);

    if (redirect_json == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    cJSON *location = cJSON_GetObjectItem(redirect_json, "location");
    cJSON *status = cJSON_GetObjectItem(redirect_json, "status_code");

    if (location == NULL || status == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    if (status->valueint <= 0) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    size_t target_len = strlen(location->valuestring);

    if(target_len > 0) {
        // Set target
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);

        if (r->headers_out.location == NULL) {
            return ngx_http_redirectionio_headers_filter(r);
        }

        // Copy string
        u_char *target = ngx_pcalloc(r->pool, target_len);
        ngx_memcpy(target, location->valuestring, target_len);

        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = target_len;
        r->headers_out.location->value.data = target;
    }

    ctx->is_redirected = 1;
    r->headers_out.status = status->valueint;

    cJSON_Delete(redirect_json);

    // @TODO This will made a double body response (one from nginx / one from upstream)
    // @TODO Find a way to cancel the current body response
    return ngx_http_special_response_handler(r, r->headers_out.status);
}

ngx_int_t ngx_http_redirectionio_headers_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    const char                      *filter_id, *headers_str, *new_headers_str;
    char                            *hname, *hvalue;
    cJSON                           *headers, *header, *new_headers, *item, *name, *value;
    ngx_uint_t                      i;
    ngx_table_elt_t                 *h;
    ngx_list_part_t                 *part;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (ctx->matched_rule == NULL) {
        return ngx_http_next_header_filter(r);
    }

    // Replace headers
    headers = cJSON_CreateArray();
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

        hname = strndup((const char *)h[i].key.data, h[i].key.len);
        hvalue = strndup((const char *)h[i].value.data, h[i].value.len);

        header = cJSON_CreateObject();
        cJSON_AddItemToObject(header, "name", cJSON_CreateString((const char *)hname));
        cJSON_AddItemToObject(header, "value", cJSON_CreateString((const char *)hvalue));

        cJSON_AddItemToArray(headers, header);

        free(hname);
        free(hvalue);
    }

    headers_str = cJSON_PrintUnformatted(headers);
    new_headers_str = redirectionio_header_filter(ctx->matched_rule_str, headers_str);

    if (new_headers_str == NULL) {
        return ngx_http_next_header_filter(r);
    }

    new_headers = cJSON_Parse(new_headers_str);

    if (new_headers == NULL || headers->type != cJSON_Array) {
        return ngx_http_next_header_filter(r);
    }

    // Deactivate all old headers
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

    // Create body filter
    filter_id = redirectionio_create_body_filter(ctx->matched_rule_str);

    if (filter_id != NULL && strlen(filter_id) != 0) {
        ctx->filter_id = filter_id;
        r->headers_out.content_length_n = -1;
    }

    return ngx_http_next_header_filter(r);
}

ngx_int_t ngx_http_redirectionio_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_chain_t                     *chain, *new_chain, *last_chain, *first_chain;
    const char                      *buf_in, *buf_out;
    size_t                          bsize;
    ngx_uint_t                      last_buf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    // Skip if no context
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    // Skip if no filter_id
    if (ctx->filter_id == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    chain = in;
    new_chain = NULL;
    last_chain = NULL;
    first_chain = NULL;
    last_buf = 0;

    while (chain != NULL) {
        if (chain->buf != NULL) {
            bsize = ngx_buf_size(chain->buf);

            if (bsize > 0) {
                buf_in = malloc(bsize + 1);
                ngx_memcpy((char *)buf_in, chain->buf, bsize);
                *((char *)buf_in + bsize) = '\0';

                buf_out = redirectionio_body_filter(ctx->filter_id, buf_in);

                if (buf_out != NULL && strlen(buf_out) > 0) {
                    new_chain = ngx_alloc_chain_link(r->pool);
                    new_chain->buf = ngx_calloc_buf(r->pool);
                    new_chain->next = NULL;

                    new_chain->buf->pos = (u_char *)buf_out;
                    new_chain->buf->last = new_chain->buf->pos + strlen(buf_out);
                    new_chain->buf->memory = 1;
                    new_chain->buf->last_buf = 0;
                    new_chain->buf->last_in_chain = 0;

                    if (last_chain != NULL) {
                        last_chain->next = new_chain;
                    } else {
                        first_chain = new_chain;
                    }

                    last_chain = new_chain;
                }
            }

            // If last buf
            if (chain->buf->last_buf == 1) {
                last_buf = 1;
                buf_out = redirectionio_body_filter_end(ctx->filter_id);

                if (buf_out != NULL && strlen(buf_out) > 0) {
                    new_chain = ngx_alloc_chain_link(r->pool);
                    new_chain->buf = ngx_calloc_buf(r->pool);
                    new_chain->next = NULL;

                    new_chain->buf->pos = (u_char *)buf_out;
                    new_chain->buf->last = new_chain->buf->pos + strlen(buf_out);
                    new_chain->buf->memory = 1;
                    new_chain->buf->last_buf = 1;
                    new_chain->buf->last_in_chain = 0;

                    if (last_chain != NULL) {
                        last_chain->next = new_chain;
                    } else {
                        first_chain = new_chain;
                    }

                    last_chain = new_chain;
                } else if (last_chain != NULL) {
                    last_chain->buf->last_buf = 1;
                }
            }
        }

        chain = chain->next;
    }

    if (last_chain != NULL) {
        last_chain->buf->last_in_chain = 1;
    }

    if (first_chain != NULL) {
        return ngx_http_next_body_filter(r, first_chain);
    }

    // Something bad happen if we receive last buf and no current buffer return old buffer
    if (last_buf) {
        return ngx_http_next_body_filter(r, in);
    }

    return NGX_OK;
}
