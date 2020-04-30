#include <ngx_http_redirectionio_module.h>

static ngx_chain_t* ngx_http_redirectionio_body_filter_replace(struct REDIRECTIONIO_FilterBodyAction *body_filter, ngx_pool_t *pool, ngx_chain_t *cl);

ngx_int_t ngx_http_redirectionio_match_on_response_status_header_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    unsigned short                  redirect_status_code;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    if (ctx->action == NULL) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    // Copy string
    redirect_status_code = redirectionio_action_get_status_code(ctx->action, r->headers_out.status);

    if (redirect_status_code == 0) {
        return ngx_http_redirectionio_headers_filter(r);
    }

    r->headers_out.status = redirect_status_code;

    return ngx_http_special_response_handler(r, r->headers_out.status);
}

ngx_int_t ngx_http_redirectionio_headers_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_uint_t                      i;
    ngx_table_elt_t                 *h;
    ngx_list_part_t                 *part;
    struct REDIRECTIONIO_HeaderMap  *first_header = NULL, *current_header = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (ctx->action == NULL) {
        return ngx_http_next_header_filter(r);
    }

    // Replace headers
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
        current_header->name = ngx_pcalloc(r->pool, h[i].key.len + 1);
        current_header->value = ngx_pcalloc(r->pool, h[i].value.len + 1);
        current_header->next = first_header;

        ngx_memcpy((char *)current_header->name, h[i].key.data, h[i].key.len);
        *((char *)current_header->name + h[i].key.len) = '\0';

        ngx_memcpy((char *)current_header->value, h[i].value.data, h[i].value.len);
        *((char *)current_header->value + h[i].value.len) = '\0';

        first_header = current_header;
    }

    first_header = (struct REDIRECTIONIO_HeaderMap *)redirectionio_action_header_filter_filter(ctx->action, first_header, r->headers_out.status);

    if (first_header == NULL) {
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

    current_header = first_header;

    while (first_header != NULL) {
        if (first_header->name == NULL || first_header->value == NULL) {
            continue;
        }

        h = ngx_list_push(&r->headers_out.headers);

        if (h == NULL) {
            current_header = first_header->next;

            // Free
            free((void *)first_header->name);
            free((void *)first_header->value);
            free((void *)first_header);

            first_header = current_header;

            continue;
        }

        h->hash = 1;

        h->key.len = strlen(first_header->name);
        h->key.data = ngx_pcalloc(r->pool, h->key.len);
        ngx_memcpy(h->key.data, first_header->name, h->key.len);

        h->value.len = strlen(first_header->value);
        h->value.data = ngx_pcalloc(r->pool, h->value.len);
        ngx_memcpy(h->value.data, first_header->value, h->value.len);

        current_header = first_header->next;

        // Free
        free((void *)first_header->name);
        free((void *)first_header->value);
        free((void *)first_header);

        first_header = current_header;
    }

    // Create body filter
    ctx->body_filter = (struct REDIRECTIONIO_FilterBodyAction *)redirectionio_action_body_filter_create(ctx->action, r->headers_out.status);

    if (ctx->body_filter != NULL) {
        // Remove content length header
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
    if (ctx->body_filter == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    out = NULL;
    ll = NULL;
    tsize = 0;

    for (cl = in; cl; cl = cl->next) {
        tl = ngx_http_redirectionio_body_filter_replace(ctx->body_filter, r->pool, cl);

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

static ngx_chain_t* ngx_http_redirectionio_body_filter_replace(struct REDIRECTIONIO_FilterBodyAction *body_filter, ngx_pool_t *pool, ngx_chain_t *cl) {
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

    buf_out = redirectionio_action_body_filter_filter(body_filter, buf_in);
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
        buf_out = redirectionio_action_body_filter_close(body_filter);

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
