#include <ngx_http_redirectionio_module.h>

static ngx_int_t ngx_http_redirectionio_get_connection(ngx_peer_connection_t *pc, void *data);

static void ngx_http_redirectionio_read_handler(ngx_event_t *rev);
static void ngx_http_redirectionio_dummy_handler(ngx_event_t *wev);

static void ngx_http_redirectionio_json_cleanup(void *data);

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
    ngx_http_redirectionio_log_t    *log = (ngx_http_redirectionio_log_t *)data;
    ngx_peer_connection_t           *peer = (ngx_peer_connection_t *)resource;

    if (peer == NULL) {
        ngx_http_redirectionio_protocol_free_log(log);

        return NGX_ERROR;
    }

    ngx_http_redirectionio_protocol_send_log(peer->connection, log);
    ngx_http_redirectionio_protocol_free_log(log);
    ngx_http_redirectionio_release_resource(reslist, resource, 0);

    return NGX_OK;
}

void ngx_http_redirectionio_release_resource(ngx_reslist_t *reslist, ngx_http_redirectionio_resource_t *resource, ngx_uint_t in_error) {
    if (in_error) {
        ngx_reslist_invalidate(reslist, resource);

        return;
    }

    resource->usage++;

    if (resource->usage > NGX_HTTP_REDIRECTIONIO_RESOURCE_MAX_USAGE) {
        ngx_reslist_invalidate(reslist, resource);

        return;
    }

    ngx_reslist_release(reslist, resource);
}

static ngx_int_t ngx_http_redirectionio_get_connection(ngx_peer_connection_t *pc, void *data) {
    return NGX_OK;
}

static void ngx_http_redirectionio_read_handler(ngx_event_t *rev) {
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_redirectionio_ctx_t    *ctx;
    u_char                          *buffer;
    u_char                          read;
    size_t                          len = 0;
    ngx_uint_t                      max_size = 8192;
    ssize_t                         readed;
    ngx_pool_cleanup_t              *cln;

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    ctx->resource->peer.connection->read->handler = ngx_http_redirectionio_dummy_handler;
    buffer = (u_char *) ngx_pcalloc(c->pool, max_size);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] connection timeout while reading, skipping module for this request");

        ctx->connection_error = 1;
        ctx->read_handler(rev, NULL);

        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for (;;) {
        readed = ngx_recv(c, &read, 1);

        if (readed == -1) { /* Error */
            ctx->connection_error = 1;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[redirectionio] connection error while reading, skipping module for this request");
            ctx->read_handler(rev, NULL);

            return;
        }

        if (readed == 0) { /* EOF */
            ctx->connection_error = 1;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[redirectionio] connection terminated while reading, skipping module for this request");
            ctx->read_handler(rev, NULL);

            return;
        }

        if (len > max_size) { /* Too big */
            ctx->connection_error = 1;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] message too big while reading, skipping module for this request");
            ctx->read_handler(rev, NULL);

            return;
        }

        if (read == '\0') { /* Message readed, push it to the current handler */
            if (len == 0) {
                continue;
            }

            *buffer = '\0';
            cJSON *json = cJSON_Parse((char *)(buffer - len));

            cln = ngx_pool_cleanup_add(r->pool, 0);
            cln->handler = ngx_http_redirectionio_json_cleanup;
            cln->data = json;

            ctx->read_handler(rev, json);

            return;
        }

        len++;
        *buffer = read;
        buffer++;
    }
}

static void ngx_http_redirectionio_dummy_handler(ngx_event_t *wev) {
    return;
}

static void ngx_http_redirectionio_json_cleanup(void *data) {
    cJSON_Delete((cJSON *)data);
}
