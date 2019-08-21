#include <ngx_http_redirectionio_module.h>

static ngx_chain_t* ngx_http_redirectionio_body_filter_replace(const char *filter_id, ngx_pool_t *pool, ngx_chain_t *cl);

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

    // Copy string
    u_char *origin_url = ngx_pnalloc(r->pool, r->unparsed_uri.len + 1);
    ngx_memcpy(origin_url, r->unparsed_uri.data, r->unparsed_uri.len);
    *(origin_url + r->unparsed_uri.len) = '\0';

    redirect = redirectionio_get_redirect(ctx->matched_rule_str, (const char *)origin_url, r->headers_out.status);

    if (redirect == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    cJSON *redirect_json = cJSON_Parse(redirect);

    if (redirect_json == NULL) {
        free((char *)redirect);

        return ngx_http_redirectionio_headers_filter(r);
    }

    cJSON *location = cJSON_GetObjectItem(redirect_json, "location");
    cJSON *status = cJSON_GetObjectItem(redirect_json, "status_code");

    if (location == NULL || status == NULL) {
        cJSON_Delete(redirect_json);
        free((char *)redirect);

        return ngx_http_redirectionio_headers_filter(r);
    }

    if (status->valueint <= 0) {
        cJSON_Delete(redirect_json);
        free((char *)redirect);

        return ngx_http_redirectionio_headers_filter(r);
    }

    size_t target_len = strlen(location->valuestring);

    if(target_len > 0) {
        // Set target
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);

        if (r->headers_out.location == NULL) {
            cJSON_Delete(redirect_json);
            free((char *)redirect);

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
    free((char *)redirect);

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

        hname = malloc(h[i].key.len + 1);
        ngx_memcpy(hname, h[i].key.data, h[i].key.len);
        *(hname + h[i].key.len) = '\0';

        hvalue = malloc(h[i].value.len + 1);
        ngx_memcpy(hvalue, h[i].value.data, h[i].value.len);
        *(hvalue + h[i].value.len) = '\0';

        header = cJSON_CreateObject();
        cJSON_AddItemToObject(header, "name", cJSON_CreateString((const char *)hname));
        cJSON_AddItemToObject(header, "value", cJSON_CreateString((const char *)hvalue));

        cJSON_AddItemToArray(headers, header);

        free(hname);
        free(hvalue);
    }

    headers_str = cJSON_PrintUnformatted(headers);
    new_headers_str = redirectionio_header_filter(ctx->matched_rule_str, headers_str);
    cJSON_Delete(headers);
    free((char*) headers_str);

    if (new_headers_str == NULL) {
        return ngx_http_next_header_filter(r);
    }

    new_headers = cJSON_Parse(new_headers_str);

    if (new_headers == NULL || new_headers->type != cJSON_Array) {
        free((char*) new_headers_str);

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

        // Not used skip it
        if (h[i].hash == 0 || h[i].value.len <= 0 || h[i].key.len <= 0) {
            continue;
        }

        h[i].hash = 0;
        h[i].value.len = 0;
    }

    item = new_headers->child;

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

        h->key.len = strlen(name->valuestring);
        h->key.data = ngx_pcalloc(r->pool, h->key.len);
        ngx_memcpy(h->key.data, name->valuestring, h->key.len);

        h->value.len = strlen(value->valuestring);
        h->value.data = ngx_pcalloc(r->pool, h->value.len);
        ngx_memcpy(h->value.data, value->valuestring, h->value.len);
    }

    cJSON_Delete(new_headers);
    free((char *)new_headers_str);

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
    ngx_chain_t                     *out, *cl, *tl, *ll;
    size_t                          tsize;
    ngx_int_t                       rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    // Skip if no context
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    // Discard body if last buffer already sent (avoid double body)
    if (ctx->last_buffer_sent == 1) {
        return ngx_http_next_body_filter(r, NULL);
    }

    // Skip if no filter_id
    if (ctx->filter_id == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    out = NULL;
    ll = NULL;
    tsize = 0;

    for (cl = in; cl; cl = cl->next) {
        tl = ngx_http_redirectionio_body_filter_replace(ctx->filter_id, r->pool, cl);

        // Last link is not null, set the next of it to the current one
        if (ll != NULL) {
            ll->next = tl;
        } else {
            out = tl;
        }

        ll = tl;
        tsize += ngx_buf_size(cl->buf);

        if (tl->buf->last_buf) {
            ctx->last_buffer_sent = 1;
        }
    }

    rc = NGX_OK;

    // Everything is buffered
    if (out != NULL) {
        rc = ngx_http_next_body_filter(r, out);
    }

    // Fake initial chain as sent
    in = ngx_chain_update_sent(in, tsize);

    return rc;
}

static ngx_chain_t* ngx_http_redirectionio_body_filter_replace(const char *filter_id, ngx_pool_t *pool, ngx_chain_t *cl) {
    ngx_chain_t                     *out = NULL, *el = NULL;
    const char                      *buf_in, *buf_out;
    char                            *memory_buf;
    size_t                          bsize, mbsize;

    bsize = ngx_buf_size(cl->buf);

    if (bsize <= 0) {
        return cl;
    }

    buf_in = malloc(bsize + 1);
    ngx_memcpy((char *)buf_in, cl->buf->pos, bsize);
    *((char *)buf_in + bsize) = '\0';

    buf_out = redirectionio_body_filter(filter_id, buf_in);
    free((char *)buf_in);

    if (buf_out != NULL && strlen(buf_out) > 0) {
        mbsize = strlen(buf_out);

        out = ngx_palloc(pool, sizeof(ngx_chain_t));

        if (out == NULL) {
            return cl;
        }

        memory_buf = ngx_palloc(pool, mbsize);
        ngx_memcpy(memory_buf, buf_out, mbsize);
        free((char *)buf_out);

        out->next = NULL;
        out->buf = ngx_create_temp_buf(pool, mbsize);

        if (out->buf == NULL) {
            return cl;
        }

        out->buf->pos = (u_char *)memory_buf;
        out->buf->last = out->buf->pos + mbsize;
        out->buf->last_buf = 0;
        out->buf->last_in_chain = cl->buf->last_in_chain;
        out->buf->tag = (ngx_buf_tag_t) &ngx_http_redirectionio_module;
    }

    if (cl->buf->last_buf == 1) {
        buf_out = redirectionio_body_filter_end(filter_id);

        if (buf_out == NULL || strlen(buf_out) == 0) {
            if (out != NULL) {
                out->buf->last_buf = 1;

                return out;
            }

            return cl;
        }

        mbsize = strlen(buf_out);
        el = ngx_palloc(pool, sizeof(ngx_chain_t));

        if (el == NULL) {
            if (out != NULL) {
                out->buf->last_buf = 1;

                return out;
            }

            return cl;
        }

        memory_buf = ngx_palloc(pool, mbsize);
        ngx_memcpy(memory_buf, buf_out, mbsize);
        free((char *)buf_out);

        el->next = NULL;
        el->buf = ngx_create_temp_buf(pool, mbsize);

        if (out->buf == NULL) {
            if (out != NULL) {
                out->buf->last_buf = 1;

                return out;
            }

            return cl;
        }

        el->buf->pos = (u_char *)memory_buf;
        el->buf->last = out->buf->pos + mbsize;
        el->buf->last_buf = 1;
        el->buf->last_in_chain = 1;
        el->buf->tag = (ngx_buf_tag_t) &ngx_http_redirectionio_module;

        if (out == NULL) {
            return el;
        }

        out->next = el;
    }

    if (out != NULL) {
        return out;
    }

    return cl;
}
