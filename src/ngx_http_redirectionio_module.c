#include <ngx_http_redirectionio_module.h>

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

static ngx_int_t ngx_http_redirectionio_postconfiguration(ngx_conf_t *cf);

static ngx_int_t ngx_http_redirectionio_create_ctx_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r);

static void ngx_http_redirectionio_write_match_action_handler(ngx_event_t *wev);
static void ngx_http_redirectionio_read_match_action_handler(ngx_event_t *rev, const char *action_serialized);
static void ngx_http_redirectionio_log_callback(const char* log_str, const void* data, short level);

static void ngx_http_redirectionio_context_cleanup(void *context);

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
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_redirectionio_set_url,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, pass),
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

    redirect_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_ACCESS_PHASE].handlers);

    if (redirect_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing redirect handler");
        return NGX_ERROR;
    }

    *redirect_handler = ngx_http_redirectionio_redirect_handler;

    // Create context handler -> pre access phase
    create_ctx_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_ACCESS_PHASE].handlers);

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
        ctx->action_string_len = 0;
        ctx->action_string_readed = 0;
        ctx->connection_error = 0;
        ctx->wait_for_connection = 0;
        ctx->last_buffer_sent = 0;
        ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;
        ctx->project_key.len = 0;
        ctx->scheme.len = 0;
        ctx->host.len = 0;

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

        redirectionio_log_init_with_callback(ngx_http_redirectionio_log_callback, r->connection->log);
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
        ngx_http_redirectionio_write_match_action_handler(ctx->resource->peer.connection->write);

        // Handle when direct error after write
        if (ctx->connection_error) {
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
        return NGX_DECLINED;
    }

    r->headers_out.status = redirect_status_code;

    return r->headers_out.status;
}

static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t   *conf;
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_log_t    *log;

    // Disallow in sub request
    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return NGX_DECLINED;
    }

    if (conf->enable_logs == NGX_HTTP_REDIRECTIONIO_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return NGX_DECLINED;
    }

    log = ngx_http_redirectionio_protocol_create_log(r, ctx, &ctx->project_key);

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

    return conf;
}

static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_redirectionio_conf_t       *prev = parent;
    ngx_http_redirectionio_conf_t       *conf = child;

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

    if (conf->pass.url.data == NULL) {
        if (prev->pass.url.data) {
            conf->pass = prev->pass;
            // Limit number of connection pool
            conf->connection_pool = prev->connection_pool;
        } else {
            // Should create new connection pool
            conf->pass.url = (ngx_str_t)ngx_string("127.0.0.1:10301");

            if (ngx_parse_url(cf->pool, &conf->pass) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if(ngx_reslist_create(
                &conf->connection_pool,
                cf->pool,
                RIO_MIN_CONNECTIONS,
                RIO_KEEP_CONNECTIONS,
                RIO_MAX_CONNECTIONS,
                RIO_DEFAULT_TIMEOUT,
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
            RIO_MIN_CONNECTIONS,
            RIO_KEEP_CONNECTIONS,
            RIO_MAX_CONNECTIONS,
            RIO_DEFAULT_TIMEOUT,
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
    char  *p = conf;

    ngx_url_t *field;
    ngx_str_t *value;
    ngx_conf_post_t  *post;

    field = (ngx_url_t *) (p + cmd->offset);

    if (field->url.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    field->url = value[1];

    if (ngx_parse_url(cf->pool, field) != NGX_OK) {
        return field->err;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static void ngx_http_redirectionio_write_match_action_handler(ngx_event_t *wev) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_connection_t                *c;
    ngx_http_request_t              *r;

    c = wev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    ngx_add_timer(c->read, RIO_DEFAULT_TIMEOUT);
    ctx->read_handler = ngx_http_redirectionio_read_match_action_handler;

    ngx_http_redirectionio_protocol_send_match(c, r, ctx, &ctx->project_key);
}

static void ngx_http_redirectionio_read_match_action_handler(ngx_event_t *rev, const char *action_serialized) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_request_t              *r;
    ngx_connection_t                *c;

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

    ngx_http_core_run_phases(r);
}

void ngx_http_redirectionio_read_dummy_handler(ngx_event_t *rev, const char *json) {
    return;
}

static void ngx_http_redirectionio_log_callback(const char* log_str, const void* data, short level) {
    if (level <= 1) {
        ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)data, 0, "redirectionio api error: %s", log_str);
    }

    free((char *)log_str);
}

static void ngx_http_redirectionio_context_cleanup(void *context) {
    struct REDIRECTIONIO_HeaderMap  *first_header, *tmp_header;
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
        first_header = (struct REDIRECTIONIO_HeaderMap *)ctx->response_headers;

        while (first_header != NULL) {
            tmp_header = first_header->next;

            free((void *)first_header->name);
            free((void *)first_header->value);
            free((void *)first_header);

            first_header = tmp_header;
        }

        ctx->response_headers = NULL;
    }

    if (ctx->body_filter != NULL) {
        redirectionio_action_body_filter_drop(ctx->body_filter);
        ctx->body_filter = NULL;
    }
}
