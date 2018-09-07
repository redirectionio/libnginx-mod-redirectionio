#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <redirectionio.h>

#define NGX_HTTP_REDIRECTIONIO_OFF     0
#define NGX_HTTP_REDIRECTIONIO_ON      1

#define ngx_str_to_go_str(ngx) (GoString){ ngx.data, ngx.len }

typedef struct {
    ngx_uint_t  enable;
    ngx_uint_t  enable_logs;
    ngx_str_t   project_key;
    ngx_str_t   instance_name;
    ngx_str_t   api_host;
    ngx_str_t   user_agent;
    ngx_str_t   data_directory;
    ngx_uint_t  debug;
    ngx_uint_t  persist;
    ngx_uint_t  cache;
} ngx_http_redirectionio_conf_t;

/**
 * List of values for boolean
 */
static ngx_conf_enum_t  ngx_http_redirectionio_enable_state[] = {
    { ngx_string("off"), NGX_HTTP_REDIRECTIONIO_OFF },
    { ngx_string("on"), NGX_HTTP_REDIRECTIONIO_ON },
    { ngx_null_string, 0 }
};

// Create default configuration
static void *ngx_http_redirectionio_create_conf(ngx_conf_t *cf);
// Merge configuration
static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redirectionio_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_redirectionio_init_process(ngx_cycle_t *cycle);

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
        ngx_string("redirectionio_instance_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, instance_name),
        NULL
    },
    {
        ngx_string("redirectionio_host"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, api_host),
        NULL
    },
    {
        ngx_string("redirectionio_datadir"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, data_directory),
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
        ngx_string("redirectionio_debug"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, debug),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_persist"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, persist),
        ngx_http_redirectionio_enable_state
    },
    {
        ngx_string("redirectionio_cache"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_redirectionio_conf_t, cache),
        ngx_http_redirectionio_enable_state
    },
    ngx_null_command /* command termination */
};


/* The module context. */
static ngx_http_module_t ngx_http_redirectionio_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_redirectionio_init, /* postconfiguration */

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
    ngx_http_redirectionio_init_process, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_redirectionio_init_process(ngx_cycle_t *cycle) {
    ngx_log_stderr(0, "redirectionio: init process");

    redirectionio_init();

    ngx_log_stderr(0, "redirectionio: init process ok");

    return NGX_OK;
}

/**
 * Init
 *
 * Add handlers where needed
 */
static ngx_int_t ngx_http_redirectionio_init(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);

    if (h == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): error pushing handler");
        return NGX_ERROR;
    }

    redirectionio_init();

    *h = ngx_http_redirectionio_log_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->cycle->log, 0, "redirectionio: init(): return OK");

    return NGX_OK;
}

/**
 * RedirectionIO Middleware
 *
 * Call at every request
 */
static ngx_int_t ngx_http_redirectionio_redirect_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        // Call next handler
        return NGX_DECLINED;
    }

    // Start agent
//    redirectionio_start_agent(
//        ngx_str_to_go_str(conf->project_key),
//        ngx_str_to_go_str(conf->instance_name),
//        ngx_str_to_go_str(conf->api_host),
//        conf->debug,
//        ngx_str_to_go_str(conf->user_agent),
//        ngx_str_to_go_str(conf->data_directory),
//        conf->persist,
//        conf->cache
//    );

    // Get uri and check if we need to redirect

    // No need to redirect -> next handler

    // Need to redirect -> return redirection response
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_redirectionio_log_handler(ngx_http_request_t *r) {
    ngx_http_redirectionio_conf_t *conf;
    ngx_log_t                     *log = r->connection->log;

    ngx_log_stderr(0, "redirectionio: log_handler()");

    conf = ngx_http_get_module_loc_conf(r, ngx_http_redirectionio_module);

    if (conf->enable == NGX_HTTP_REDIRECTIONIO_OFF) {
        ngx_log_stderr(0, "redirectionio: redirectionio is off");
        return NGX_DECLINED;
    }

    if (conf->enable_logs == NGX_HTTP_REDIRECTIONIO_OFF) {
        ngx_log_stderr(0, "redirectionio: redirectionio logs is off");
        return NGX_DECLINED;
    }

    ngx_log_stderr(0, "redirectionio: starting agent");

    // Start agent
    redirectionio_start_agent(
        (GoString){"58056a48-664d-11e7-aeb0-0242ac130004",36},
        ngx_str_to_go_str(conf->instance_name),
        (GoString){"https://api.redirection-io.test/app_dev.php",43},
//        ngx_str_to_go_str(conf->api_host),
        1,
        ngx_str_to_go_str(conf->user_agent),
        ngx_str_to_go_str(conf->data_directory),
        0,
        conf->cache
    );

    ngx_log_stderr(0, "redirectionio: agent is started");

    // Get request and response needed data

    // Log it
    return NGX_DECLINED;
}

/* Create configuration object */
static void *ngx_http_redirectionio_create_conf(ngx_conf_t *cf) {
    ngx_http_redirectionio_conf_t *conf;

    conf = (ngx_http_redirectionio_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_redirectionio_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->enable_logs = NGX_CONF_UNSET;
    conf->debug = NGX_CONF_UNSET;
    conf->persist = NGX_CONF_UNSET;
    conf->cache = NGX_CONF_UNSET;

    return conf;
}

static char *ngx_http_redirectionio_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_redirectionio_conf_t *prev = parent;
    ngx_http_redirectionio_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable, NGX_HTTP_REDIRECTIONIO_OFF);
    ngx_conf_merge_uint_value(conf->enable_logs, prev->enable_logs, NGX_HTTP_REDIRECTIONIO_ON);
    ngx_conf_merge_uint_value(conf->debug, prev->debug, NGX_HTTP_REDIRECTIONIO_OFF);
    ngx_conf_merge_uint_value(conf->persist, prev->persist, NGX_HTTP_REDIRECTIONIO_ON);
    ngx_conf_merge_uint_value(conf->cache, prev->cache, NGX_HTTP_REDIRECTIONIO_ON);

    ngx_conf_merge_str_value(conf->project_key, prev->project_key, "");
    // @TODO Get hostname here ?
    ngx_conf_merge_str_value(conf->instance_name, prev->instance_name, "");
    ngx_conf_merge_str_value(conf->api_host, prev->api_host, "https://api.redirection.io");
    ngx_conf_merge_str_value(conf->data_directory, prev->data_directory, "/var/lib/redirectionio");
    ngx_conf_merge_str_value(conf->user_agent, prev->user_agent, "Nginx RedirectionIo Module");

    return NGX_CONF_OK;
}
