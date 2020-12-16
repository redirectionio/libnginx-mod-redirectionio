#include <ngx_http_redirectionio_module.h>

static ngx_int_t ngx_http_redirectionio_get_connection(ngx_peer_connection_t *pc, void *data);

static void ngx_http_redirectionio_dummy_handler(ngx_event_t *wev);

static ngx_int_t ngx_http_redirectionio_read_uint32(ngx_connection_t *c, uint32_t *uint32);

static ngx_int_t ngx_http_redirectionio_read_string(ngx_connection_t *c, char *string, ssize_t buf_size, ssize_t *readed);

ngx_int_t ngx_http_redirectionio_pool_construct(void **rp, void *params) {
    ngx_pool_t                          *pool;
    ngx_http_redirectionio_resource_t   *resource;
    ngx_int_t                           rc;
    ngx_http_redirectionio_conf_t       *conf = (ngx_http_redirectionio_conf_t *)params;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);

    if (pool == NULL) {
        return NGX_ERROR;
    }

    resource = ngx_pcalloc(pool, sizeof(ngx_http_redirectionio_resource_t));

    if (resource == NULL) {
        return NGX_ERROR;
    }

    resource->pool = pool;
    resource->peer.sockaddr = (struct sockaddr *)&conf->pass.sockaddr;
    resource->peer.socklen = conf->pass.socklen;
    resource->peer.name = &conf->pass.url;
    resource->peer.get = ngx_http_redirectionio_get_connection;
    resource->peer.log = pool->log;
    resource->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&resource->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (resource->peer.connection) {
            ngx_close_connection(resource->peer.connection);
        }

        return NGX_ERROR;
    }

    int tcp_nodelay = 1;

    if (setsockopt(resource->peer.connection->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_socket_errno,  "setsockopt(TCP_NODELAY) %V failed, ignored", &resource->peer.connection->addr_text);
    }

    resource->peer.connection->pool = pool;
    resource->peer.connection->read->handler = ngx_http_redirectionio_dummy_handler;
    resource->peer.connection->write->handler = ngx_http_redirectionio_dummy_handler;

    *rp = resource;

    return NGX_OK;
}

ngx_int_t ngx_http_redirectionio_pool_destruct(void *rp, void *params) {
    ngx_http_redirectionio_resource_t   *resource = (ngx_http_redirectionio_resource_t *)rp;

    ngx_close_connection(resource->peer.connection);
    ngx_destroy_pool(resource->pool);

    return NGX_OK;
}

ngx_int_t ngx_http_redirectionio_pool_available(ngx_reslist_t *reslist, void *resource, void *data, ngx_int_t deferred) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_request_t              *r = (ngx_http_request_t *)data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] no context, skipping module for this request");

        if (deferred) {
            ngx_http_core_run_phases(r);
        }

        return NGX_ERROR;
    }

    ctx->wait_for_connection = 0;

    if (resource == NULL) {
        ctx->connection_error = 1;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] cannot acquire connection, retrieving resource from pool timed out, skipping module for this request");

        if (deferred) {
            ngx_http_core_run_phases(r);
        }

        return NGX_ERROR;
    }

    ctx->resource = (ngx_http_redirectionio_resource_t *)resource;
    ctx->resource->peer.connection->data = r;
    ctx->resource->peer.connection->read->handler = ngx_http_redirectionio_read_handler;

    if (deferred) {
        ngx_http_core_run_phases(r);
    }

    return NGX_OK;
}

ngx_int_t ngx_http_redirectionio_pool_available_log_handler(ngx_reslist_t *reslist, void *resource, void *data, ngx_int_t deferred) {
    ngx_http_redirectionio_log_t       *log = (ngx_http_redirectionio_log_t *)data;
    ngx_http_redirectionio_resource_t  *rr = (ngx_http_redirectionio_resource_t *)resource;
    ngx_int_t                          rv;

    if (rr == NULL) {
        ngx_http_redirectionio_protocol_free_log(log);

        return NGX_ERROR;
    }

    rv = ngx_http_redirectionio_protocol_send_log(rr->peer.connection, log);
    ngx_http_redirectionio_protocol_free_log(log);

    if (rv != NGX_OK) {
        ngx_reslist_invalidate(reslist, rr);
    } else {
        ngx_reslist_release(reslist, rr);
    }

    return NGX_OK;
}

void ngx_http_redirectionio_release_resource(ngx_reslist_t *reslist, ngx_http_redirectionio_ctx_t *ctx, ngx_uint_t in_error) {
    if (ctx->resource == NULL) {
        return;
    }

    ctx->resource->usage++;

    if (!in_error && ctx->resource->usage < NGX_HTTP_REDIRECTIONIO_RESOURCE_MAX_USAGE) {
        ngx_reslist_release(reslist, ctx->resource);
    } else {
        ngx_reslist_invalidate(reslist, ctx->resource);
    }

    ctx->resource = NULL;
    ctx->wait_for_connection = 0;
    ctx->connection_error = 0;
}

static ngx_int_t ngx_http_redirectionio_get_connection(ngx_peer_connection_t *pc, void *data) {
    return NGX_OK;
}

void ngx_http_redirectionio_read_handler(ngx_event_t *rev) {
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_int_t                       rv;

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (rev->timedout) {
        ctx->connection_error = 1;
        ctx->read_handler(rev, NULL);
        ctx->resource->peer.connection->read->handler = ngx_http_redirectionio_dummy_handler;

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] connection timeout while reading, skipping module for this request");

        return;
    }

    if (ctx->action_string_len == 0) {
        // Read uint32
        rv = ngx_http_redirectionio_read_uint32(c, &ctx->action_string_len);

        if (rv != NGX_OK) {
            ctx->connection_error = 1;
            ctx->read_handler(rev, NULL);
            ctx->resource->peer.connection->read->handler = ngx_http_redirectionio_dummy_handler;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] connection error while reading length, skipping module for this request");

            if (rev->timer_set) {
                ngx_del_timer(rev);
            }

            return;
        }

        ctx->action_string = (char *)ngx_pcalloc(r->pool, ctx->action_string_len + 1);
    }

    rv = ngx_http_redirectionio_read_string(c, ctx->action_string, ctx->action_string_len, &ctx->action_string_readed);

    if (rv == NGX_AGAIN) {
        return;
    }

    if (rv != NGX_OK) {
        ctx->connection_error = 1;
        ctx->read_handler(rev, NULL);
        ctx->resource->peer.connection->read->handler = ngx_http_redirectionio_dummy_handler;

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] connection error while reading string: %d, skipping module for this request", rv);

        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    ctx->resource->peer.connection->read->handler = ngx_http_redirectionio_dummy_handler;
    ctx->read_handler(rev, (const char *)ctx->action_string);
}

static void ngx_http_redirectionio_dummy_handler(ngx_event_t *wev) {
    return;
}

static ngx_int_t ngx_http_redirectionio_read_uint32(ngx_connection_t *c, uint32_t *uint32) {
    ssize_t     srlen = sizeof(uint32_t);
    ssize_t     serlen = sizeof(uint32_t);
    ssize_t     sdrlen = 0;

    while (sdrlen < serlen) {
        srlen = ngx_recv(c, (u_char *)(uint32 + sdrlen), srlen);

        if (srlen <= 0) {
            return srlen;
        }

        sdrlen += srlen;
        srlen = serlen - sdrlen;
    }

    *uint32 = ntohl(*uint32);

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_read_string(ngx_connection_t *c, char *string, ssize_t buf_size, ssize_t *readed) {
    ssize_t     srlen = buf_size;

    while (*readed < buf_size) {
        srlen = ngx_recv(c, (u_char *)(string + *readed), buf_size - *readed);

        if (srlen < 0) {
            return srlen;
        }

        *readed += srlen;
    }

    *(string + buf_size) = '\0';

    return NGX_OK;
}
