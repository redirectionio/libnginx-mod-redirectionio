#include <ngx_http_redirectionio_module.h>

static ngx_chain_t* ngx_http_redirectionio_body_filter_replace(ngx_http_redirectionio_ctx_t *ctx, ngx_pool_t *pool, ngx_chain_t *cl);

static ngx_int_t ngx_http_redirectionio_create_filter_body(ngx_http_request_t *r);

static ngx_int_t ngx_http_redirectionio_header_read(ngx_http_request_t *r, ngx_table_elt_t *header, struct REDIRECTIONIO_HeaderMap **first);

static ngx_int_t ngx_http_redirectionio_header_content_type_read(ngx_http_request_t *r, struct REDIRECTIONIO_HeaderMap **first);

static ngx_int_t ngx_http_redirectionio_buffer_read(ngx_buf_t *buffer, struct REDIRECTIONIO_Buffer *output);

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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio status code update %d (on response status code)", redirect_status_code);

    r->headers_out.status = redirect_status_code;
    r->headers_out.status_line = (ngx_str_t)ngx_null_string;

    return ngx_http_redirectionio_headers_filter(r);
}

ngx_int_t ngx_http_redirectionio_headers_filter(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_uint_t                      i;
    ngx_table_elt_t                 *h;
    ngx_list_part_t                 *part;
    struct REDIRECTIONIO_HeaderMap  *header_map = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf == NULL || conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio start header filter");

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

        ngx_http_redirectionio_header_read(r, &h[i], &header_map);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio add filter to send \"%s: %s\"", header_map->name, header_map->value);
    }

    // Copy specific headers
    ngx_http_redirectionio_header_content_type_read(r, &header_map);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio filtering on response status code %d", r->headers_out.status);
    header_map = (struct REDIRECTIONIO_HeaderMap *)redirectionio_action_header_filter_filter(ctx->action, header_map, r->headers_out.status, conf->show_rule_ids == NGX_HTTP_REDIRECTIONIO_ON);

    if (header_map == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio no filter to add");

        return ngx_http_redirectionio_create_filter_body(r);
    }

    ctx->response_headers = header_map;

    // Deactivate all old headers
    part = &r->headers_out.headers.part;
    h = part->elts;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio header filter clean");

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

    while (header_map != NULL) {
        if (header_map->name == NULL || header_map->value == NULL) {
            header_map = header_map->next;

            continue;
        }

        // Handle specific headers
        if (ngx_strcasecmp((u_char *)header_map->name, (u_char *)"Content-Type") == 0) {
            header_map = header_map->next;

            continue;
        }

        h = ngx_list_push(&r->headers_out.headers);

        if (h == NULL) {
            header_map = header_map->next;

            continue;
        }

        h->hash = 1;

        h->key.len = strlen(header_map->name);
        h->key.data = ngx_pcalloc(r->pool, h->key.len);
        ngx_memcpy(h->key.data, header_map->name, h->key.len);

        h->value.len = strlen(header_map->value);
        h->value.data = ngx_pcalloc(r->pool, h->value.len);
        ngx_memcpy(h->value.data, header_map->value, h->value.len);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio add header to response \"%s: %s\"", header_map->name, header_map->value);

        if (ngx_strcasecmp((u_char *)header_map->name, (u_char *)"Content-Encoding") == 0) {
            r->headers_out.content_encoding = h;
        }

        header_map = header_map->next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio header filter done");

    return ngx_http_redirectionio_create_filter_body(r);
}

static ngx_int_t ngx_http_redirectionio_create_filter_body(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (ctx->action == NULL) {
        return ngx_http_next_header_filter(r);
    }

    // Create body filter
    ctx->body_filter = (struct REDIRECTIONIO_FilterBodyAction *)redirectionio_action_body_filter_create(ctx->action, r->headers_out.status);

    if (ctx->body_filter != NULL) {
        // Remove content length header
        r->headers_out.content_length_n = -1;
    }

    return ngx_http_next_header_filter(r);
}

ngx_int_t ngx_http_redirectionio_body_filter(ngx_http_request_t *r, ngx_chain_t *input_chain) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_chain_t                     *out_chain, *current_chain, *tmp_chain, *last_chain, *previous_chain;
    size_t                          tsize;
    ngx_int_t                       rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return ngx_http_next_body_filter(r, input_chain);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    // Skip if no context
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, input_chain);
    }

    // Discard body if last buffer already sent (avoid double body)
    if (ctx->last_buffer_sent == 1) {
        return ngx_http_next_body_filter(r, NULL);
    }

    // Skip if no filter_id
    if (ctx->body_filter == NULL) {
        return ngx_http_next_body_filter(r, input_chain);
    }

    if (input_chain == NULL) {
        return ngx_http_next_body_filter(r, input_chain);
    }

    out_chain = NULL;
    last_chain = NULL;
    previous_chain = NULL;
    tsize = 0;

    for (current_chain = input_chain; current_chain; current_chain = current_chain->next) {
        tmp_chain = ngx_http_redirectionio_body_filter_replace(ctx, r->pool, current_chain);

        // Buffered case
        if (tmp_chain == NULL) {
            continue;
        }

        // Error case: receive same thing as sended
        if (tmp_chain == current_chain) {
            // Add chain to the one sent, and remove from in (so it's not updated)
            if (previous_chain == NULL) {
                input_chain = current_chain->next;
            } else {
                previous_chain->next = current_chain->next;
            }
        } else {
            previous_chain = current_chain;
            tsize += ngx_buf_size(current_chain->buf);
        }

        // Last chain is not null, set the next of it to the current one
        if (last_chain != NULL) {
            last_chain->next = tmp_chain;
        } else {
            out_chain = tmp_chain;
        }

        last_chain = tmp_chain;

        if (tmp_chain->buf->last_buf) {
            ctx->last_buffer_sent = 1;
        }
    }

    rc = NGX_OK;

    // Everything is buffered
    if (out_chain != NULL) {
        rc = ngx_http_next_body_filter(r, out_chain);
    }

    // Fake initial chain as sent (only if not null, as we may have used old ones already)
    if (input_chain != NULL) {
        input_chain = ngx_chain_update_sent(input_chain, tsize);
    }

    return rc;
}

static ngx_chain_t* ngx_http_redirectionio_body_filter_replace(ngx_http_redirectionio_ctx_t *ctx, ngx_pool_t *pool, ngx_chain_t *cl) {
    ngx_chain_t                     *out = NULL, *el = NULL;
    struct REDIRECTIONIO_Buffer     buf_in, buf_out;
    char                            *memory_buf;
    size_t                          mbsize;

    if (ngx_http_redirectionio_buffer_read(cl->buf, &buf_in) != NGX_OK) {
        return cl;
    }

    buf_out = redirectionio_action_body_filter_filter(ctx->body_filter, buf_in);

    // Same output as input
    if (buf_out.data == buf_in.data) {
        return cl;
    }

    if (buf_out.len > 0) {
        mbsize = buf_out.len;
        out = ngx_palloc(pool, sizeof(ngx_chain_t));

        if (out == NULL) {
            return cl;
        }

        memory_buf = ngx_palloc(pool, mbsize);
        ngx_memcpy(memory_buf, buf_out.data, mbsize);
        redirectionio_api_buffer_drop(buf_out);

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
        buf_out = redirectionio_action_body_filter_close(ctx->body_filter);
        ctx->body_filter = NULL;

        if (buf_out.len == 0) {
            if (out != NULL) {
                out->buf->last_buf = 1;

                return out;
            }

            return cl;
        }

        mbsize = buf_out.len;
        el = ngx_palloc(pool, sizeof(ngx_chain_t));

        if (el == NULL) {
            if (out != NULL) {
                out->buf->last_buf = 1;

                return out;
            }

            return cl;
        }

        memory_buf = ngx_palloc(pool, mbsize);
        ngx_memcpy(memory_buf, buf_out.data, mbsize);
        redirectionio_api_buffer_drop(buf_out);

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

    return out;
}

static ngx_int_t ngx_http_redirectionio_header_read(ngx_http_request_t *r, ngx_table_elt_t *header, struct REDIRECTIONIO_HeaderMap **first) {
    struct REDIRECTIONIO_HeaderMap  *new_header;

    new_header = (struct REDIRECTIONIO_HeaderMap *)ngx_pcalloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));
    new_header->name = ngx_pcalloc(r->pool, header->key.len + 1);
    new_header->value = ngx_pcalloc(r->pool, header->value.len + 1);
    new_header->next = *first;

    ngx_memcpy((char *)new_header->name, header->key.data, header->key.len);
    *((char *)new_header->name + header->key.len) = '\0';

    ngx_memcpy((char *)new_header->value, header->value.data, header->value.len);
    *((char *)new_header->value + header->value.len) = '\0';

    *first = new_header;

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_header_content_type_read(ngx_http_request_t *r, struct REDIRECTIONIO_HeaderMap **first) {
    struct REDIRECTIONIO_HeaderMap  *new_header;
    ngx_uint_t                      len = 0;

    if (r->headers_out.content_type.len) {
        len += r->headers_out.content_type.len + 1;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len && r->headers_out.charset.len) {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (len == 0) {
        return NGX_OK;
    }

    new_header = (struct REDIRECTIONIO_HeaderMap *)ngx_pcalloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));
    new_header->name = "Content-Type";
    new_header->value = ngx_pcalloc(r->pool, len);
    new_header->next = *first;

    ngx_memcpy((char *)new_header->value, r->headers_out.content_type.data, r->headers_out.content_type.len);

    if (r->headers_out.content_type_len == r->headers_out.content_type.len && r->headers_out.charset.len) {
        ngx_memcpy((char *)new_header->value, "; charset=", sizeof("; charset=") - 1);
        ngx_memcpy((char *)new_header->value, r->headers_out.charset.data, r->headers_out.charset.len);
    }

    *((char *)new_header->value + len) = '\0';
    *first = new_header;

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_buffer_read(ngx_buf_t *buffer, struct REDIRECTIONIO_Buffer *output) {
#if (NGX_HAVE_SENDFILE64)
    off_t   offset;
#else
    int32_t offset;
#endif
    size_t  bsize, readed = 0;
    ssize_t n;

    bsize = ngx_buf_size(buffer);

    if (bsize <= 0) {
        return NGX_DONE;
    }

    if (!ngx_buf_in_memory(buffer) && !buffer->in_file) {
        return NGX_DONE;
    }

    output->data = malloc(bsize);
    output->len = bsize;

    if (ngx_buf_in_memory(buffer)) {
        ngx_memcpy(output->data, buffer->pos, bsize);
    } else if (buffer->in_file) {
#if (NGX_HAVE_SENDFILE64)
        offset = buffer->file_pos;
#else
        offset = (int32_t) buffer->file_pos;
#endif
        while (readed < bsize) {
            n = pread(buffer->file->fd, output->data, bsize - readed, offset + readed);

            if (n <= 0) {
                free(output->data);
                output->len = 0;

                return NGX_ERROR;
            }

            readed += n;
        }
    }

    return NGX_OK;
}
