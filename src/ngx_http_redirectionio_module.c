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

static void ngx_http_redirectionio_write_match_rule_handler(ngx_event_t *wev);
static void ngx_http_redirectionio_read_match_rule_handler(ngx_event_t *rev, cJSON *json, const char *json_str);

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
        ngx_conf_set_str_slot,
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
        ngx_string("redirectionio_pass"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_redirectionio_set_url,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, pass),
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

#ifdef NGX_HTTP_PRECONTENT_PHASE
    redirect_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
#else
    redirect_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
#endif

    if (redirect_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing redirect handler");
        return NGX_ERROR;
    }

    *redirect_handler = ngx_http_redirectionio_redirect_handler;

    // Create context handler -> pre access phase
    create_ctx_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

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
        ctx->matched_rule_status = API_NOT_CALLED;
        ctx->matched_rule_str = NULL;
        ctx->matched_rule = NULL;
        ctx->filter_id = NULL;
        ctx->connection_error = 0;
        ctx->wait_for_connection = 0;
        ctx->is_redirected = 0;
        ctx->read_handler = NULL;
        ctx->body_buffer = NULL;
        ctx->last_chain_sent = NULL;
//        ctx->body_sent = 0;
//        ctx->read_binary_handler = NULL;
//        ctx->first_buffer = 1;

        ngx_http_set_ctx(r, ctx, ngx_http_redirectionio_module);
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
    const char                      *redirect;
    ngx_table_elt_t                 *header_location;

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
    if (ctx->matched_rule_status == API_WAITING) {
        return NGX_AGAIN;
    }

    // if api not called call it and return ngx_again to wait for response
    if (ctx->matched_rule_status == API_NOT_CALLED) {
        ctx->matched_rule_status = API_WAITING;
        ngx_http_redirectionio_write_match_rule_handler(ctx->resource->peer.connection->write);

        return NGX_AGAIN;
    }

    // Here api has been called and result has been set, free resource from pool
    ngx_http_redirectionio_release_resource(conf->connection_pool, ctx, 0);

    // If no rule matched (error or something else) do not do anything more
    if (ctx->matched_rule == NULL) {
        return NGX_DECLINED;
    }

    // Get redirect before response
    redirect = redirectionio_get_redirect(ctx->matched_rule_str, (const char *)r->unparsed_uri.data, 0);

    if (redirect == NULL) {
        return NGX_DECLINED;
    }

    cJSON *redirect_json = cJSON_Parse(redirect);

    if (redirect_json == NULL) {
        free((char *)redirect);

        return NGX_DECLINED;
    }

    cJSON *location = cJSON_GetObjectItem(redirect_json, "location");
    cJSON *status_code = cJSON_GetObjectItem(redirect_json, "status_code");

    if (location == NULL || status_code == NULL) {
        cJSON_Delete(redirect_json);
        free((char *)redirect);

        return NGX_DECLINED;
    }

    if (status_code->valueint <= 0) {
        cJSON_Delete(redirect_json);
        free((char *)redirect);

        return NGX_DECLINED;
    }

    size_t target_len = strlen(location->valuestring);

    if(target_len > 0) {
        // Set target
        header_location = ngx_list_push(&r->headers_out.headers);

        if (header_location == NULL) {
            cJSON_Delete(redirect_json);
            free((char *)redirect);

            return NGX_DECLINED;
        }

        // Copy string
        u_char *target = ngx_pcalloc(r->pool, target_len);
        ngx_memcpy(target, location->valuestring, target_len);

        header_location->hash = 1;
        ngx_str_set(&header_location->key, "Location");
        header_location->value.len = target_len;
        header_location->value.data = target;
    }

    ctx->is_redirected = 1;
    r->headers_out.status = status_code->valueint;

    cJSON_Delete(redirect_json);
    free((char *)redirect);

    return r->headers_out.status;
}

static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t   *conf;
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_redirectionio_log_t    *log;
    cJSON                           *rule_id_json;
    ngx_str_t                       rule_id = ngx_null_string;

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

    if (ctx->matched_rule != NULL) {
        rule_id_json = cJSON_GetObjectItem(ctx->matched_rule, "id");

        if (rule_id_json != NULL) {
            rule_id.len = strlen(rule_id_json->valuestring);
            rule_id.data = malloc(rule_id.len);
            ngx_memcpy(rule_id.data, rule_id_json->valuestring, rule_id.len);
        }
    }

    log = ngx_http_redirectionio_protocol_create_log(r, &conf->project_key, &rule_id);
    free(rule_id.data);

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

    return conf;
}

static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_redirectionio_conf_t       *prev = parent;
    ngx_http_redirectionio_conf_t       *conf = child;

    ngx_conf_merge_uint_value(conf->enable_logs, prev->enable_logs, NGX_HTTP_REDIRECTIONIO_ON);
    ngx_conf_merge_str_value(conf->project_key, prev->project_key, "");

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
                RIO_TIMEOUT,
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
            RIO_TIMEOUT,
            conf,
            ngx_http_redirectionio_pool_construct,
            ngx_http_redirectionio_pool_destruct
        ) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[redirectionio] cannot create connection pool for redirectionio, disabling module");

            conf->enable = NGX_HTTP_REDIRECTIONIO_OFF;
        }
    }

    if (conf->project_key.len > 0) {
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

static void ngx_http_redirectionio_write_match_rule_handler(ngx_event_t *wev) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_redirectionio_conf_t   *conf;

    c = wev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    ngx_add_timer(c->read, RIO_TIMEOUT);
    ctx->read_handler = ngx_http_redirectionio_read_match_rule_handler;

    ngx_http_redirectionio_protocol_send_match(c, r, &conf->project_key);
}

static void ngx_http_redirectionio_read_match_rule_handler(ngx_event_t *rev, cJSON *json, const char *json_str) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_request_t              *r;
    ngx_connection_t                *c;

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;
    ctx->matched_rule_status = API_CALLED;

    if (json == NULL) {
        ngx_http_core_run_phases(r);

        return;
    }

    ctx->matched_rule = json;
    ctx->matched_rule_str = json_str;

    ngx_http_core_run_phases(r);
}

void ngx_http_redirectionio_read_dummy_handler(ngx_event_t *rev, cJSON *json, const char *json_str) {
    return;
}


