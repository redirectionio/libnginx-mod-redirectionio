#include <ngx_http_redirectionio_module.h>

ngx_http_output_header_filter_pt    ngx_http_next_header_filter;
ngx_http_output_body_filter_pt      ngx_http_next_body_filter;
ngx_module_t                        ngx_http_redirectionio_module;

/**
 * List of values for boolean
 */
static ngx_conf_enum_t  ngx_http_redirectionio_enable_state[] = {
    { ngx_string("off"), NGX_HTTP_REDIRECTIONIO_OFF },
    { ngx_string("on"), NGX_HTTP_REDIRECTIONIO_ON },
    { ngx_null_string, 0 }
};

static void *ngx_http_redirectionio_create_conf(ngx_conf_t *cf);
static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_redirectionio_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_redirectionio_set_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_redirectionio_set_trusted_proxies(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_redirectionio_trace_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_redirectionio_postconfiguration(ngx_conf_t *cf);

static ngx_int_t ngx_http_redirectionio_create_ctx_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_filter_request_headers(ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx);
static void ngx_http_redirectionio_request_headers_filtered(void *data);
#if (nginx_version < 1023000)
static ngx_uint_t ngx_http_redirectionio_is_multi_header(ngx_str_t *name);
#endif

static ngx_int_t ngx_http_redirectionio_write_match_action(ngx_event_t *wev);
static void ngx_http_redirectionio_write_match_action_handler(ngx_event_t *wev);
static void ngx_http_redirectionio_read_match_action_handler(ngx_event_t *rev, const char *action_serialized);

static void ngx_http_redirectionio_context_cleanup(void *context);
static void ngx_http_redirectionio_trusted_proxies_cleanup(void *trusted_proxies);

/**
 * Commands definitions
 */
static ngx_command_t ngx_http_redirectionio_commands[] = {
    {
        ngx_string("redirectionio"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, enable),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_project_key"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, project_key),
        NULL
    },
    {
        ngx_string("redirectionio_logs"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, enable_logs),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_add_rule_ids_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, show_rule_ids),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_pass"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
        ngx_http_redirectionio_set_url,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, server),
        NULL
    },
    {
        ngx_string("redirectionio_scheme"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, scheme),
        NULL
    },
    {
        ngx_string("redirectionio_host"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, host),
        NULL
    },
    {
        ngx_string("redirectionio_set_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
        ngx_http_redirectionio_set_header,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, headers_set),
        NULL
    },
    {
        ngx_string("redirectionio_trusted_proxies"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_redirectionio_set_trusted_proxies,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, headers_set),
        NULL
    },
    {
        ngx_string("redirectionio_trace_enable"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_DIRECT_CONF|NGX_CONF_NOARGS,
        ngx_http_redirectionio_trace_enable,
        0,
        0,
        NULL
    },
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_redirectionio_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_redirectionio_postconfiguration, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_redirectionio_create_conf, /* create location configuration */
    ngx_http_redirectionio_merge_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_redirectionio_module = {
    NGX_MODULE_V1,
    &ngx_http_redirectionio_module_ctx, /* module context */
    ngx_http_redirectionio_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_redirectionio_postconfiguration(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t           *cmcf;
    ngx_http_handler_pt                 *create_ctx_handler;
    ngx_http_handler_pt                 *redirect_handler;
    ngx_http_handler_pt                 *log_handler;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // Log handler -> log phase
    log_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);

    if (log_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing log handler");
        return NGX_ERROR;
    }

    *log_handler = ngx_http_redirectionio_log_handler;

    redirect_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (redirect_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing redirect handler");
        return NGX_ERROR;
    }

    *redirect_handler = ngx_http_redirectionio_redirect_handler;

    // Create context handler -> pre access phase
    create_ctx_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (create_ctx_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing ctx handler");
        return NGX_ERROR;
    }

    *create_ctx_handler = ngx_http_redirectionio_create_ctx_handler;

    // Filters
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_redirectionio_match_on_response_status_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_redirectionio_body_filter;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): return OK");

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_create_ctx_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_conf_t   *conf;
    ngx_pool_cleanup_t              *cln;

    // Disallow in sub request
    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        ctx = (ngx_http_redirectionio_ctx_t *) ngx_pcalloc(r->pool, sizeof(ngx_http_redirectionio_ctx_t));

        if (ctx == NULL) {
            return NGX_DECLINED;
        }

        ctx->resource = NULL;
        ctx->matched_action_status = API_NOT_CALLED;
        ctx->request = NULL;
        ctx->action = NULL;
        ctx->response_headers = NULL;
        ctx->body_filter = NULL;
        ctx->action_string = NULL;
        ctx->action_match_time = 0;
        ctx->proxy_response_time = 0;
        ctx->action_string_len = 0;
        ctx->action_string_readed = 0;
        ctx->connection_error = 0;
        ctx->wait_for_connection = 0;
        ctx->last_buffer_sent = 0;
        ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;
        ctx->project_key.len = 0;
        ctx->scheme.len = 0;
        ctx->host.len = 0;
        ctx->backend_response_status_code = 0;

        if (ngx_http_complex_value(r, conf->project_key, &ctx->project_key) != NGX_OK) {
            return NGX_DECLINED;
        }

        if (conf->scheme != NULL && ngx_http_complex_value(r, conf->scheme, &ctx->scheme) != NGX_OK) {
            return NGX_DECLINED;
        }

        if (conf->host != NULL && ngx_http_complex_value(r, conf->host, &ctx->host) != NGX_OK) {
            return NGX_DECLINED;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);

        if (cln == NULL) {
            return NGX_DECLINED;
        }

        cln->data = ctx;
        cln->handler = ngx_http_redirectionio_context_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_redirectionio_module);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio init context");
    }

    return NGX_DECLINED;
}
/**
 * RedirectionIO Middleware
 *
 * Call at every request
 */
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t   *conf;
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_int_t                       status;
    unsigned short                  redirect_status_code;

    // Disallow in sub request
    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        // Call next handler
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return NGX_DECLINED;
    }

    if (ctx->connection_error) {
        if (ctx->resource != NULL) {
            ngx_http_redirectionio_release_resource(conf->connection_pool, ctx, 1);
        }

        ctx->wait_for_connection = 0;
        ctx->resource = NULL;
        ctx->connection_error = 0;

        return NGX_DECLINED;
    }

    if (ctx->resource == NULL) {
        if (ctx->wait_for_connection) {
            return NGX_AGAIN;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio acquire connection from pool");

        status = ngx_reslist_acquire(conf->connection_pool, ngx_http_redirectionio_pool_available, r);

        if (status == NGX_AGAIN) {
            ctx->wait_for_connection = 1;

            return status;
        }

        if (status != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    // return NGX_AGAIN while waiting for api response
    if (ctx->matched_action_status == API_WAITING) {
        return NGX_AGAIN;
    }

    // if api not called call it and return ngx_again to wait for response
    if (ctx->matched_action_status == API_NOT_CALLED) {
        ctx->matched_action_status = API_WAITING;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio call match action");
        status = ngx_http_redirectionio_write_match_action(ctx->resource->peer.connection->write);

        if (status == NGX_AGAIN) {
            ngx_log_debug0(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] send again");
            ctx->resource->peer.connection->write->handler = ngx_http_redirectionio_write_match_action_handler;

            return NGX_AGAIN;
        }

        // Handle when direct error after write
        if (status != NGX_OK || ctx->connection_error) {
            if (ctx->resource != NULL) {
                ngx_http_redirectionio_release_resource(conf->connection_pool, ctx, 1);
            }

            ctx->wait_for_connection = 0;
            ctx->resource = NULL;
            ctx->connection_error = 0;

            return NGX_DECLINED;
        }

        return NGX_AGAIN;
    }

    // Here api has been called and result has been set, free resource from pool
    ngx_http_redirectionio_release_resource(conf->connection_pool, ctx, 0);

    // If no rule matched (error or something else) do not do anything more
    if (ctx->action == NULL) {
        return NGX_DECLINED;
    }

    redirect_status_code = redirectionio_action_get_status_code(ctx->action, 0);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio status code before backend call %d", redirect_status_code);

    if (redirect_status_code == 0) {
        if (ngx_http_redirectionio_filter_request_headers(r, ctx) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[redirectionio] cannot filter request headers");
        }

        return NGX_DECLINED;
    }

    r->headers_out.status = redirect_status_code;

    // Force special response for 2XX request
    ngx_http_finalize_request(r, ngx_http_special_response_handler(r, r->headers_out.status));

    return NGX_DONE;
}

/**
 * Replace the request headers forwarded to the backend with the ones filtered by the action.
 *
 * ngx_list_t cannot remove an element, so the list is rebuilt, and the shortcuts of
 * ngx_http_headers_in_t are pointed to the new elements.
 */
static ngx_int_t ngx_http_redirectionio_filter_request_headers(ngx_http_request_t *r, ngx_http_redirectionio_ctx_t *ctx) {
    ngx_http_core_main_conf_t               *cmcf;
    ngx_http_header_t                       *hh;
    ngx_pool_cleanup_t                      *cln;
    ngx_list_t                              headers;
    ngx_list_part_t                         *part;
    ngx_table_elt_t                         *h, **ph;
    ngx_uint_t                              i, count = 0;
    struct REDIRECTIONIO_HeaderMap          *reversed_headers, *first_header = NULL, *current_header, *next_header;
    const struct REDIRECTIONIO_HeaderMap    *filtered_headers, *filtered_header;
#if (nginx_version < 1023000)
    ngx_array_t                             *multi_headers;
#endif

    // An internal redirect clears the module context and matches again, but the headers must
    // only be filtered once: remember it with a cleanup, which survives the redirect
    for (cln = r->pool->cleanup; cln != NULL; cln = cln->next) {
        if (cln->handler == ngx_http_redirectionio_request_headers_filtered) {
            return NGX_OK;
        }
    }

    reversed_headers = ngx_http_redirectionio_protocol_capture_request_headers(r, 0);

    for (current_header = reversed_headers; current_header != NULL; current_header = next_header) {
        next_header = current_header->next;
        current_header->next = first_header;
        first_header = current_header;
    }

    filtered_headers = redirectionio_action_request_header_filter_filter(ctx->action, first_header);

    // No request header filter for this action: leave the request untouched
    if (filtered_headers == NULL) {
        return NGX_OK;
    }

    for (filtered_header = filtered_headers; filtered_header != NULL; filtered_header = filtered_header->next) {
        count++;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL || ngx_list_init(&headers, r->pool, count > 0 ? count : 1, sizeof(ngx_table_elt_t)) != NGX_OK) {
        redirectionio_header_map_drop(filtered_headers);

        return NGX_ERROR;
    }

    cln->handler = ngx_http_redirectionio_request_headers_filtered;
    cln->data = NULL;

    for (filtered_header = filtered_headers; filtered_header != NULL; filtered_header = filtered_header->next) {
        if (filtered_header->name == NULL || filtered_header->value == NULL || filtered_header->name[0] == '\0') {
            continue;
        }

        h = ngx_list_push(&headers);

        if (h == NULL) {
            redirectionio_header_map_drop(filtered_headers);

            return NGX_ERROR;
        }

        // Keep the strings null terminated, as the request parser does
        h->key.len = ngx_strlen(filtered_header->name);
        h->key.data = ngx_pnalloc(r->pool, h->key.len + 1);
        h->value.len = ngx_strlen(filtered_header->value);
        h->value.data = ngx_pnalloc(r->pool, h->value.len + 1);
        h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);

        if (h->key.data == NULL || h->value.data == NULL || h->lowcase_key == NULL) {
            redirectionio_header_map_drop(filtered_headers);

            return NGX_ERROR;
        }

        ngx_memcpy(h->key.data, filtered_header->name, h->key.len + 1);
        ngx_memcpy(h->value.data, filtered_header->value, h->value.len + 1);
        h->hash = ngx_hash_strlow(h->lowcase_key, h->key.data, h->key.len);
#if (nginx_version >= 1023000)
        h->next = NULL;
#endif
    }

    redirectionio_header_map_drop(filtered_headers);

    r->headers_in.headers = headers;

    // Same as ngx_http_process_request_headers, without its handlers: protected headers (host,
    // content length, connection...) are never changed by the filter, so what they computed holds
    for (hh = ngx_http_headers_in; hh->name.len > 0; hh++) {
#if (nginx_version < 1023000)
        if (ngx_http_redirectionio_is_multi_header(&hh->name)) {
            ((ngx_array_t *) ((char *) &r->headers_in + hh->offset))->nelts = 0;

            continue;
        }
#endif

        *((ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset)) = NULL;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
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

        hh = ngx_hash_find(&cmcf->headers_in_hash, h[i].hash, h[i].lowcase_key, h[i].key.len);

        if (hh == NULL) {
            continue;
        }

#if (nginx_version < 1023000)
        if (ngx_http_redirectionio_is_multi_header(&hh->name)) {
            multi_headers = (ngx_array_t *) ((char *) &r->headers_in + hh->offset);

            if (multi_headers->elts == NULL && ngx_array_init(multi_headers, r->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK) {
                return NGX_ERROR;
            }

            ph = ngx_array_push(multi_headers);

            if (ph == NULL) {
                return NGX_ERROR;
            }

            *ph = &h[i];

            continue;
        }

        ph = (ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset);

        if (*ph == NULL) {
            *ph = &h[i];
        }
#else
        ph = (ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset);

        while (*ph != NULL) {
            ph = &(*ph)->next;
        }

        *ph = &h[i];
#endif
    }

    return NGX_OK;
}

static void ngx_http_redirectionio_request_headers_filtered(void *data) {
}

#if (nginx_version < 1023000)
// Before 1.23, these headers are collected in an array instead of a linked list
static ngx_uint_t ngx_http_redirectionio_is_multi_header(ngx_str_t *name) {
    if (name->len == sizeof("Cookie") - 1 && ngx_strncasecmp(name->data, (u_char *) "Cookie", name->len) == 0) {
        return 1;
    }

#if (NGX_HTTP_X_FORWARDED_FOR)
    if (name->len == sizeof("X-Forwarded-For") - 1 && ngx_strncasecmp(name->data, (u_char *) "X-Forwarded-For", name->len) == 0) {
        return 1;
    }
#endif

    return 0;
}
#endif

static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t   *conf;
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_log_t    *log;
    bool                            should_log;

    // Disallow in sub request
    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return NGX_DECLINED;
    }

    // When logging is disabled at the module level (yaml configuration), the request is
    // not logged and its rules are not counted: the user opted this proxy out of traffic
    // visibility.
    if (conf->enable_logs == NGX_HTTP_REDIRECTIONIO_OFF) {
        return NGX_DECLINED;
    }

    should_log = redirectionio_action_should_log_request(ctx->action, true, ctx->backend_response_status_code);

    if (should_log) {
        log = ngx_http_redirectionio_protocol_create_log(r, ctx, &ctx->project_key);
    } else if (redirectionio_action_agent_supports_rule_count(ctx->action)) {
        // Logging was disabled for this request by a "configuration" action: still count
        // the executed rules, without sending the full request log. Only when the agent
        // understands the RULE_COUNT command (protocol >= 1.1), as advertised in the match
        // response; sending it to an older agent would make it reject the unknown command
        // and close the pooled connection, corrupting later requests.
        log = ngx_http_redirectionio_protocol_create_rule_count(ctx, &ctx->project_key);
    } else {
        // Older agent without rule-count support: nothing to send for this request.
        log = NULL;
    }

    if (log == NULL) {
        return NGX_DECLINED;
    }

    ngx_reslist_acquire(conf->connection_pool, ngx_http_redirectionio_pool_available_log_handler, log);

    return NGX_DECLINED;
}

/* Create configuration object */
static void *ngx_http_redirectionio_create_conf(ngx_conf_t *cf) {
    ngx_http_redirectionio_conf_t   *conf;

    conf = (ngx_http_redirectionio_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_redirectionio_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->enable_logs = NGX_CONF_UNSET_UINT;
    conf->show_rule_ids = NGX_CONF_UNSET_UINT;
    conf->server.min_conns = RIO_MIN_CONNECTIONS;
    conf->server.keep_conns = RIO_KEEP_CONNECTIONS;
    conf->server.max_conns = RIO_MAX_CONNECTIONS;
    conf->server.timeout = RIO_DEFAULT_TIMEOUT;

    if (ngx_array_init(&conf->headers_set, cf->pool, 10, sizeof(ngx_http_redirectionio_header_set_t)) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_redirectionio_conf_t       *prev = parent;
    ngx_http_redirectionio_conf_t       *conf = child;
    ngx_uint_t                          i;
    ngx_http_redirectionio_header_set_t *phs, *hs;

    ngx_conf_merge_uint_value(conf->enable_logs, prev->enable_logs, NGX_HTTP_REDIRECTIONIO_ON);
    ngx_conf_merge_uint_value(conf->show_rule_ids, prev->show_rule_ids, NGX_HTTP_REDIRECTIONIO_OFF);

    if (conf->project_key == NULL) {
        conf->project_key = prev->project_key;
    }

    if (conf->scheme == NULL) {
        conf->scheme = prev->scheme;
    }

    if (conf->host == NULL) {
        conf->host = prev->host;
    }

    if (conf->trusted_proxies == NULL) {
        conf->trusted_proxies = prev->trusted_proxies;
    }

    phs = prev->headers_set.elts;

    for (i = 0; i < prev->headers_set.nelts ; i++) {
        hs = ngx_array_push(&conf->headers_set);

        hs->name = phs[i].name;
        hs->value = phs[i].value;
    }

    if (conf->server.pass.url.data == NULL) {
        if (prev->server.pass.url.data) {
            conf->server.pass = prev->server.pass;
            conf->connection_pool = prev->connection_pool;

            // this can happens if url set in http block, as it will never be merged with parent and so connection pool will not be created,
            // so we need to create it here, we don't create it for parent, let's use a connection pool per server block
            if (conf->connection_pool == NULL) {
                if(ngx_reslist_create(
                    &conf->connection_pool,
                    cf->pool,
                    conf->server.min_conns,
                    conf->server.keep_conns,
                    conf->server.max_conns,
                    conf->server.timeout,
                    conf,
                    ngx_http_redirectionio_pool_construct,
                    ngx_http_redirectionio_pool_destruct
                ) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[redirectionio] cannot create connection pool for redirectionio, disabling module");

                    conf->enable = NGX_HTTP_REDIRECTIONIO_OFF;
                }
            }
        } else {
            // Should create new connection pool
            conf->server.pass.url = (ngx_str_t)ngx_string("127.0.0.1:10301");

            if (ngx_parse_url(cf->pool, &conf->server.pass) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if(ngx_reslist_create(
                &conf->connection_pool,
                cf->pool,
                conf->server.min_conns,
                conf->server.keep_conns,
                conf->server.max_conns,
                conf->server.timeout,
                conf,
                ngx_http_redirectionio_pool_construct,
                ngx_http_redirectionio_pool_destruct
            ) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[redirectionio] cannot create connection pool for redirectionio, disabling module");

                conf->enable = NGX_HTTP_REDIRECTIONIO_OFF;
            }
        }
    } else {
        if(ngx_reslist_create(
            &conf->connection_pool,
            cf->pool,
            conf->server.min_conns,
            conf->server.keep_conns,
            conf->server.max_conns,
            conf->server.timeout,
            conf,
            ngx_http_redirectionio_pool_construct,
            ngx_http_redirectionio_pool_destruct
        ) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[redirectionio] cannot create connection pool for redirectionio, disabling module");

            conf->enable = NGX_HTTP_REDIRECTIONIO_OFF;
        }
    }

    if (conf->project_key != NULL) {
        ngx_conf_merge_uint_value(conf->enable, prev->enable, NGX_HTTP_REDIRECTIONIO_ON);
    } else {
        ngx_conf_merge_uint_value(conf->enable, prev->enable, NGX_HTTP_REDIRECTIONIO_OFF);
    }

    return NGX_CONF_OK;
}

static char *ngx_http_redirectionio_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char                                *p = conf;
    ngx_http_redirectionio_server_t     *field;
    ngx_str_t                           *value;
    ngx_uint_t                          i;

    field = (ngx_http_redirectionio_server_t *) (p + cmd->offset);

    if (field->pass.url.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "min_conns=", 10) == 0) {
            field->min_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (field->min_conns == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {
            field->max_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (field->max_conns == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "keep_conns=", 11) == 0) {
            field->keep_conns = ngx_atoi(&value[i].data[11], value[i].len - 11);

            if (field->keep_conns == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            field->timeout = (ngx_msec_t) ngx_atoi(&value[i].data[8], value[i].len - 8);

            if (field->timeout == (ngx_msec_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    ngx_memzero(&field->pass, sizeof(ngx_url_t));

    field->pass.url = value[1];
    field->pass.default_port = 10301;

    if (ngx_parse_url(cf->pool, &field->pass) != NGX_OK) {
        if (field->pass.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in redirectionio server pass \"%V\"", field->pass.err, &field->pass.url);
        }

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static char *ngx_http_redirectionio_set_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char                                    *p = conf;
    ngx_array_t                             *headers_set;
    ngx_str_t                               *value;
    ngx_http_redirectionio_header_set_t     *h;
    ngx_http_compile_complex_value_t        ccvk, ccvv;

    headers_set = (ngx_array_t *) (p + cmd->offset);
    h = ngx_array_push(headers_set);

    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    h->name = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));

    if (h->name == NULL) {
        return NGX_CONF_ERROR;
    }

    h->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));

    if (h->value == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccvk, sizeof(ngx_http_compile_complex_value_t));
    ngx_memzero(&ccvv, sizeof(ngx_http_compile_complex_value_t));

    ccvk.cf = cf;
    ccvk.value = &value[1];
    ccvk.complex_value = h->name;

    ccvv.cf = cf;
    ccvv.value = &value[2];
    ccvv.complex_value = h->value;

    if (ngx_http_compile_complex_value(&ccvk) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccvv) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *ngx_http_redirectionio_set_trusted_proxies(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_redirectionio_conf_t           *conf = c;
    char                                    *trusted_proxies_str;
    ngx_str_t                               *value;
    ngx_pool_cleanup_t                      *cln;

    value = cf->args->elts;
    trusted_proxies_str = ngx_http_redirectionio_str_to_char(&value[1], cf->pool);

    // Register the cleanup before creating the rust object, so it cannot leak
    // if adding the cleanup fails
    cln = ngx_pool_cleanup_add(cf->pool, 0);

    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->trusted_proxies = (struct REDIRECTIONIO_TrustedProxies *) redirectionio_trusted_proxies_create((const char *)trusted_proxies_str);

    cln->data = conf->trusted_proxies;
    cln->handler = ngx_http_redirectionio_trusted_proxies_cleanup;

    return NGX_CONF_OK;
}

static char *ngx_http_redirectionio_trace_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    redirectionio_trace_init();

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_redirectionio_write_match_action(ngx_event_t *wev) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_redirectionio_conf_t   *conf;

    c = wev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    ngx_add_timer(c->read, conf->server.timeout);
    ctx->read_handler = ngx_http_redirectionio_read_match_action_handler;

    return ngx_http_redirectionio_protocol_send_match(c, r, ctx, &ctx->project_key);
}

static void ngx_http_redirectionio_write_match_action_handler(ngx_event_t *wev) {
    ngx_int_t   rv;

    wev->handler = ngx_http_redirectionio_dummy_handler;
    rv = ngx_http_redirectionio_write_match_action(wev);

    if (rv == NGX_AGAIN) {
        wev->handler = ngx_http_redirectionio_write_match_action_handler;
    }
}

static void ngx_http_redirectionio_read_match_action_handler(ngx_event_t *rev, const char *action_serialized) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_request_t              *r;
    ngx_connection_t                *c;
    ngx_time_t                      *tp;

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;
    ctx->matched_action_status = API_CALLED;

    if (action_serialized == NULL) {
        ngx_http_core_run_phases(r);

        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http redirectionio action received: %s", action_serialized);

    ctx->action = (struct REDIRECTIONIO_Action *)redirectionio_action_json_deserialize((char *)action_serialized);

    tp = ngx_timeofday();
    ctx->action_match_time = (tp->sec * 1000 + tp->msec);

    ngx_http_core_run_phases(r);
}

void ngx_http_redirectionio_read_dummy_handler(ngx_event_t *rev, const char *json) {
    return;
}

static void ngx_http_redirectionio_context_cleanup(void *context) {
    ngx_http_redirectionio_ctx_t    *ctx = (ngx_http_redirectionio_ctx_t *)context;

    if (ctx->action != NULL) {
        redirectionio_action_drop(ctx->action);
        ctx->action = NULL;
    }

    if (ctx->request != NULL) {
        redirectionio_request_drop(ctx->request);
        ctx->request = NULL;
    }

    if (ctx->response_headers != NULL) {
        redirectionio_header_map_drop(ctx->response_headers);
        ctx->response_headers = NULL;
    }

    if (ctx->body_filter != NULL) {
        redirectionio_action_body_filter_drop(ctx->body_filter);
        ctx->body_filter = NULL;
    }
}

static void ngx_http_redirectionio_trusted_proxies_cleanup(void *trusted_proxies) {
    redirectionio_trusted_proxies_drop((struct REDIRECTIONIO_TrustedProxies *)trusted_proxies);
}

char* ngx_http_redirectionio_str_to_char(ngx_str_t *src, ngx_pool_t *pool) {
    char *str;

    str = (char *)ngx_pcalloc(pool, src->len + 1);
    ngx_memcpy(str, src->data, src->len);
    *((char *)str + src->len) = '\0';

    return str;
}
