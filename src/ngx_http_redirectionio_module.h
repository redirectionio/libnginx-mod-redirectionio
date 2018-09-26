#include <ngx_http_redirectionio_protocol.h>
#include <ngx_http_json.h>

#define NGX_HTTP_REDIRECTIONIO_OFF     0
#define NGX_HTTP_REDIRECTIONIO_ON      1

#define ngx_str_to_go_str(ngx) (GoString){ (const char*)ngx.data, ngx.len }

typedef struct {
    ngx_uint_t                  enable;
    ngx_uint_t                  enable_logs;
    ngx_str_t                   project_key;
    ngx_http_complex_value_t    *complex_target;
    ngx_url_t                   pass;
} ngx_http_redirectionio_conf_t;

typedef struct {
    ngx_uint_t  enable;
    ngx_str_t   instance_name;
    ngx_str_t   api_host;
    ngx_str_t   user_agent;
    ngx_str_t   data_directory;
    ngx_uint_t  debug;
    ngx_uint_t  persist;
    ngx_uint_t  cache;
    ngx_url_t   listen;
} ngx_http_redirectionio_agent_conf_t;

typedef void (*ngx_http_redirectionio_read_handler_t)(ngx_event_t *rev, cJSON *json);

typedef struct {
    ngx_peer_connection_t                   peer;
    ngx_str_t                               matched_rule_id;
    ngx_str_t                               target;
    ngx_uint_t                              status;
    ngx_http_redirectionio_read_handler_t   read_handler;
    ngx_http_request_t                      *subrequest;
} ngx_http_redirectionio_ctx_t;

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

static ngx_int_t ngx_http_redirectionio_init_process(ngx_cycle_t *cycle);
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
