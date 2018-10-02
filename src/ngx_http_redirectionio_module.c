#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <dlfcn.h>

#include <ngx_http_redirectionio_module.h>

ngx_str_t NGX_HTTP_REDIRECTIONIO_CLIENT_NAME = ngx_string("redirectionio_agent_client");

/**
 * List of values for boolean
 */
static ngx_conf_enum_t  ngx_http_redirectionio_enable_state[] = {
    { ngx_string("off"), NGX_HTTP_REDIRECTIONIO_OFF },
    { ngx_string("on"), NGX_HTTP_REDIRECTIONIO_ON },
    { ngx_null_string, 0 }
};

static void *ngx_http_redirectionio_create_agent_conf(ngx_conf_t *cf);
static char *ngx_http_redirectionio_init_agent_conf(ngx_conf_t *cf, void *child);
static void *ngx_http_redirectionio_create_conf(ngx_conf_t *cf);
static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_redirectionio_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_redirectionio_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_redirectionio_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_redirectionio_postconfiguration(ngx_conf_t *cf);

static ngx_int_t ngx_http_redirectionio_create_ctx_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_redirectionio_get_connection(ngx_peer_connection_t *pc, void *data);

static void ngx_http_redirectionio_read_handler(ngx_event_t *rev);

static void ngx_http_redirectionio_write_match_rule_handler(ngx_event_t *wev);
static void ngx_http_redirectionio_write_log_handler(ngx_event_t *wev);
static void ngx_http_redirectionio_write_dummy_handler(ngx_event_t *wev);

static void ngx_http_redirectionio_read_match_rule_handler(ngx_event_t *rev, cJSON *json);
static void ngx_http_redirectionio_read_dummy_handler(ngx_event_t *rev, cJSON *json);

static void ngx_http_redirectionio_json_cleanup(void *data);
static void ngx_redirectionio_execute_agent(ngx_cycle_t *cycle, void *data);
static void ngx_redirectionio_log_handler(unsigned char level, char* message, ngx_cycle_t *cycle);

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
        ngx_string("redirectionio_no_logs"),
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
    {
        ngx_string("redirectionio_agent_enable"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, enable),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_listen"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, listen),
        NULL
    },
    {
        ngx_string("redirectionio_host"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, api_host),
        NULL
    },
    {
        ngx_string("redirectionio_instance_name"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, instance_name),
        NULL
    },
    {
        ngx_string("redirectionio_datadir"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, data_directory),
        NULL
    },
    {
        ngx_string("redirectionio_debug"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, debug),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_persist"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, persist),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_cache"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_agent_conf_t, cache),
        ngx_http_redirectionio_enable_state
    },
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_redirectionio_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_redirectionio_postconfiguration, /* postconfiguration */

    ngx_http_redirectionio_create_agent_conf, /* create main configuration */
    ngx_http_redirectionio_init_agent_conf, /* init main configuration */

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
    ngx_http_redirectionio_init_module, /* init module */
    ngx_http_redirectionio_init_worker, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_redirectionio_init_worker(ngx_cycle_t *cycle) {
    // @TODO Init connections here
    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_init_module(ngx_cycle_t *cycle) {
    ngx_http_redirectionio_agent_conf_t *racf;

    racf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_redirectionio_module);

    if (racf->enable == NGX_HTTP_REDIRECTIONIO_ON) {
        ngx_spawn_process(cycle, ngx_redirectionio_execute_agent, racf, "redirectionio - agent", NGX_PROCESS_RESPAWN);
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_postconfiguration(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t           *cmcf;
    ngx_http_handler_pt                 *create_ctx_handler;
    ngx_http_handler_pt                 *redirect_handler;
    ngx_http_handler_pt                 *log_handler;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    log_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);

    if (log_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing log handler");
        return NGX_ERROR;
    }

    *log_handler = ngx_http_redirectionio_log_handler;

    redirect_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

    if (redirect_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing redirect handler");
        return NGX_ERROR;
    }

    *redirect_handler = ngx_http_redirectionio_redirect_handler;

    create_ctx_handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

    if (create_ctx_handler == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing ctx handler");
        return NGX_ERROR;
    }

    *create_ctx_handler = ngx_http_redirectionio_create_ctx_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): return OK");

    return NGX_OK;
}

static ngx_int_t ngx_http_redirectionio_create_ctx_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_int_t                       rc;
    ngx_http_redirectionio_conf_t   *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        return NGX_DECLINED;
    }

    ctx = (ngx_http_redirectionio_ctx_t *) ngx_pcalloc(r->pool, sizeof(ngx_http_redirectionio_ctx_t));

    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_redirectionio_module);

    ctx->peer.sockaddr = (struct sockaddr *)&conf->pass.sockaddr;
    ctx->peer.socklen = conf->pass.socklen;
    ctx->peer.name = &conf->pass.url;
    ctx->peer.get = ngx_http_redirectionio_get_connection;
    ctx->peer.log = r->connection->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->status = 0;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (ctx->peer.connection) {
            ngx_close_connection(ctx->peer.connection);
        }

        return NGX_DECLINED;
    }

    ctx->peer.connection->data = r;
    ctx->peer.connection->pool = r->connection->pool;
    ctx->peer.connection->read->handler = ngx_http_redirectionio_read_handler;
    ctx->peer.connection->write->handler = ngx_http_redirectionio_write_dummy_handler;

    return NGX_DECLINED;
}
/**
 * RedirectionIO Middleware
 *
 * Call at every request
 */
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t *conf;
    ngx_http_redirectionio_ctx_t  *ctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        // Call next handler
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);

    if (ctx == NULL) {
        return NGX_DECLINED;
    }

    if (!ctx->peer.connection) {
        return NGX_DECLINED;
    }

    if (ctx->matched_rule_id.data == NULL) {
        ngx_http_redirectionio_write_match_rule_handler(ctx->peer.connection->write);

        return NGX_AGAIN;
    }

    if (ctx->status == 0) {
        return NGX_DECLINED;
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

    return ctx->status;
}

static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t *conf;
    ngx_http_redirectionio_ctx_t  *ctx;

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

    if (!ctx->peer.connection) {
        return NGX_DECLINED;
    }

    ngx_http_redirectionio_write_log_handler(ctx->peer.connection->write);

    ngx_close_connection(ctx->peer.connection);

    return NGX_DECLINED;
}

static void *ngx_http_redirectionio_create_agent_conf(ngx_conf_t *cf) {
    ngx_http_redirectionio_agent_conf_t *conf;

    conf = (ngx_http_redirectionio_agent_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_redirectionio_agent_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->debug = NGX_CONF_UNSET_UINT;
    conf->persist = NGX_CONF_UNSET_UINT;
    conf->cache = NGX_CONF_UNSET_UINT;
    conf->enable = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *ngx_http_redirectionio_init_agent_conf(ngx_conf_t *cf, void *child) {
    ngx_http_redirectionio_agent_conf_t *conf = child;

    ngx_conf_init_uint_value(conf->debug, NGX_HTTP_REDIRECTIONIO_OFF);
    ngx_conf_init_uint_value(conf->persist, NGX_HTTP_REDIRECTIONIO_ON);
    ngx_conf_init_uint_value(conf->cache, NGX_HTTP_REDIRECTIONIO_ON);
    ngx_conf_init_uint_value(conf->enable, NGX_HTTP_REDIRECTIONIO_ON);

    if (conf->instance_name.data == NULL) {
        conf->instance_name.len = cf->cycle->hostname.len;
        conf->instance_name.data = cf->cycle->hostname.data;
    }

    if (conf->api_host.data == NULL) {
        conf->api_host = (ngx_str_t)ngx_string("https://api.redirection.io");
    }

    if (conf->data_directory.data == NULL) {
        conf->data_directory = (ngx_str_t)ngx_string("/var/lib/redirectionio");
    }

    if (conf->listen.data == NULL) {
        conf->listen = (ngx_str_t)ngx_string("127.0.0.1:10301");
    }

    return NGX_CONF_OK;
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
        } else {
            conf->pass.url = (ngx_str_t)ngx_string("127.0.0.1:10301");

            if (ngx_parse_url(cf->pool, &conf->pass) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
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


ngx_int_t ngx_http_redirectionio_get_connection(ngx_peer_connection_t *pc, void *data) {
    return NGX_OK;
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
    ctx->read_handler = ngx_http_redirectionio_read_match_rule_handler;

    ngx_http_redirectionio_protocol_send_match(c, r, &conf->project_key);
}

static void ngx_http_redirectionio_write_log_handler(ngx_event_t *wev) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_redirectionio_conf_t   *conf;

    c = wev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);
    ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;

    ngx_http_redirectionio_protocol_send_log(c, r, &conf->project_key, &ctx->matched_rule_id);
}

static void ngx_http_redirectionio_write_dummy_handler(ngx_event_t *wev) {
    return;
}

static void ngx_http_redirectionio_read_match_rule_handler(ngx_event_t *rev, cJSON *json) {
    ngx_http_redirectionio_ctx_t    *ctx;
    ngx_http_request_t              *r;
    ngx_connection_t                *c;

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_redirectionio_module);
    ctx->read_handler = ngx_http_redirectionio_read_dummy_handler;

    if (json == NULL) {
        ctx->matched_rule_id.data = (u_char *)"";
        ctx->matched_rule_id.len = 0;
        ctx->status = 0;

        ngx_http_core_run_phases(r);

        return;
    }

    cJSON *status = cJSON_GetObjectItem(json, "status_code");
    cJSON *location = cJSON_GetObjectItem(json, "location");
    cJSON *matched_rule = cJSON_GetObjectItem(json, "matched_rule");
    cJSON *rule_id = NULL;

    if (matched_rule != NULL && matched_rule->type != cJSON_NULL) {
        rule_id = cJSON_GetObjectItem(matched_rule, "id");
    }

    if (matched_rule == NULL || matched_rule->type == cJSON_NULL) {
        ctx->matched_rule_id.data = (u_char *)"";
        ctx->matched_rule_id.len = 0;
        ctx->status = 0;

        ngx_http_core_run_phases(r);

        return;
    }

    ctx->matched_rule_id.data = (u_char *)rule_id->valuestring;
    ctx->matched_rule_id.len = strlen(rule_id->valuestring);
    ctx->target.data = (u_char *)location->valuestring;
    ctx->target.len = strlen(location->valuestring);
    ctx->status = status->valueint;

    ngx_http_core_run_phases(r);
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
    buffer = (u_char *) ngx_pcalloc(c->pool, max_size);

    for (;;) {
        readed = ngx_recv(c, &read, 1);

        if (readed == -1) { /* Error */
            ctx->read_handler(rev, NULL);

            return;
        }

        if (readed == 0) { /* EOF */
            ctx->read_handler(rev, NULL);

            return;
        }

        if (len > max_size) { /* Too big */
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

static void ngx_http_redirectionio_json_cleanup(void *data) {
    cJSON_Delete((cJSON *)data);
}

static void ngx_http_redirectionio_read_dummy_handler(ngx_event_t *rev, cJSON *json) {
    return;
}

static void ngx_redirectionio_execute_agent(ngx_cycle_t *cycle, void *data) {
    ngx_http_redirectionio_agent_conf_t *racf = data;
    GoUint8                             result = 0;
    ngx_core_conf_t                     *ccf;
    redirectionio_init_func             redirectionio_init;
    redirectionio_set_log_handler_func  redirectionio_set_log_handler;
    void			                    *redirectioniolib = NULL;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // Switch group and user if root
    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno, "setgid(%d) failed", ccf->group);
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno, "initgroups(%s, %d) failed", ccf->username, ccf->group);
        }

        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno, "setuid(%d) failed", ccf->user);
            exit(2);
        }
    }

    // Other security can be added here (set cap / chdir / ....) need to see what's revelant
    ngx_setproctitle("redirectionio - agent");

    redirectioniolib = dlopen("libredirectionio.so", RTLD_NOW|RTLD_NODELETE);

    if (redirectioniolib == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno, "cannot launch redirectionio agent: dlopen libredirectionio failed: %s", dlerror());
        exit(2);
    }

    redirectionio_set_log_handler = dlsym(redirectioniolib, "redirectionio_set_log_handler");
    redirectionio_init = dlsym(redirectioniolib, "redirectionio_init");

    if (redirectionio_init == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno, "cannot launch redirectionio agent: dlsysm redirectionio_init failed: %s", dlerror());

        dlclose(redirectioniolib);
        exit(2);
    }

    if (redirectionio_set_log_handler == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno, "cannot set log handler (log will be output to stderr): dlsysm redirectionio_set_log_handler failed: %s", dlerror());
    } else {
        (*redirectionio_set_log_handler)(ngx_redirectionio_log_handler, cycle);
    }

    result = (*redirectionio_init)(
        ngx_str_to_go_str(racf->listen),
        ngx_str_to_go_str(racf->instance_name),
        ngx_str_to_go_str(racf->api_host),
        racf->debug,
        ngx_str_to_go_str(racf->data_directory),
        racf->persist,
        racf->cache
    );

    dlclose(redirectioniolib);

    exit(result);
}

static void ngx_redirectionio_log_handler(unsigned char level, char* message, ngx_cycle_t *cycle) {
    ngx_uint_t ngx_log_level;

    ngx_log_level = NGX_LOG_CRIT;

    // panic = 0, fatal = 1, error = 2, warn = 3, info = 4, debug = 5
    if (level == 2) {
        ngx_log_level = NGX_LOG_ERR;
    }

    if (level == 3) {
        ngx_log_level = NGX_LOG_WARN;
    }

    if (level == 4) {
        ngx_log_level = NGX_LOG_INFO;
    }

    if (level == 5) {
        ngx_log_level = NGX_LOG_DEBUG;
    }

    ngx_log_error(ngx_log_level, cycle->log, 0, "[redirectionio agent] %s", message);
}
