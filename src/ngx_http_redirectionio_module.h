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


typedef struct { const char *p; ptrdiff_t n; } GoString;
typedef unsigned char GoUint8;

typedef void (*redirectionio_init_func)(GoString p0, GoString p1, GoString p2, GoUint8 p3, GoString p4, GoString p5, GoUint8 p6, GoUint8 p7);
