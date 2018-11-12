#include <ngx_http_redirectionio_protocol.h>
#include <ngx_http_json.h>

#define NGX_HTTP_REDIRECTIONIO_OFF     0
#define NGX_HTTP_REDIRECTIONIO_ON      1

#define RIO_TIMEOUT 100

#define ngx_str_to_go_str(ngx) (GoString){ (const char*)ngx.data, ngx.len }

typedef struct {
    ngx_uint_t                  enable;
    ngx_uint_t                  enable_logs;
    ngx_str_t                   project_key;
    ngx_http_complex_value_t    *complex_target;
    ngx_url_t                   pass;
} ngx_http_redirectionio_conf_t;

typedef void (*ngx_http_redirectionio_read_handler_t)(ngx_event_t *rev, cJSON *json);

typedef struct {
    ngx_peer_connection_t                   peer;
    ngx_str_t                               matched_rule_id;
    ngx_str_t                               target;
    ngx_uint_t                              status;
    ngx_http_redirectionio_read_handler_t   read_handler;
    ngx_http_request_t                      *subrequest;
} ngx_http_redirectionio_ctx_t;
