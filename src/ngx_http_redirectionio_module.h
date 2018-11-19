#include <ngx_http_redirectionio_protocol.h>
#include <ngx_http_json.h>

#define NGX_HTTP_REDIRECTIONIO_OFF     0
#define NGX_HTTP_REDIRECTIONIO_ON      1

#define NGX_HTTP_REDIRECTIONIO_RESOURCE_MAX_USAGE   500

typedef struct {
    ngx_uint_t                  enable;
    ngx_uint_t                  enable_logs;
    ngx_str_t                   project_key;
    ngx_http_complex_value_t    *complex_target;
    ngx_url_t                   pass;
    ngx_reslist_t               *connection_pool;
} ngx_http_redirectionio_conf_t;

typedef void (*ngx_http_redirectionio_read_handler_t)(ngx_event_t *rev, cJSON *json);

typedef struct {
    ngx_peer_connection_t   peer;
    ngx_uint_t              usage;
    ngx_pool_t              *pool;
} ngx_http_redirectionio_resource_t;

typedef struct {
    ngx_http_redirectionio_resource_t       *resource;
    ngx_str_t                               matched_rule_id;
    ngx_str_t                               target;
    ngx_uint_t                              status;
    ngx_uint_t                              match_on_response_status;
    ngx_uint_t                              is_redirected;
    ngx_uint_t                              connection_error;
    ngx_http_redirectionio_read_handler_t   read_handler;
    ngx_uint_t                              wait_for_connection;
    ngx_uint_t                              wait_for_match;
} ngx_http_redirectionio_ctx_t;
