#ifndef redirectionio_module_h
#define redirectionio_module_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <dlfcn.h>
#include <ngx_http_pool.h>
#include <ngx_http_redirectionio_protocol.h>
#include <ngx_http_json.h>
#include <stdio.h>
#include "../../libredirectionio/target/redirectionio.h"

#define NGX_HTTP_REDIRECTIONIO_OFF     0
#define NGX_HTTP_REDIRECTIONIO_ON      1

#define RIO_MIN_CONNECTIONS 0
#define RIO_KEEP_CONNECTIONS 10
#define RIO_MAX_CONNECTIONS 10
#define RIO_TIMEOUT 100

#define API_NOT_CALLED  0
#define API_WAITING     1
#define API_CALLED      2

#define NGX_HTTP_REDIRECTIONIO_RESOURCE_MAX_USAGE   500

#ifndef PROXY_VERSION
#define PROXY_VERSION libnginx-mod-redirectionio:dev
#endif

#define STRINGIZE(x) #x
#define PROXY_VERSION_STR(x) STRINGIZE(x)

typedef struct {
    ngx_uint_t                  enable;
    ngx_uint_t                  enable_logs;
    ngx_str_t                   project_key;
    ngx_http_complex_value_t    *complex_target;
    ngx_url_t                   pass;
    ngx_reslist_t               *connection_pool;
} ngx_http_redirectionio_conf_t;

typedef void (*ngx_http_redirectionio_read_handler_t)(ngx_event_t *rev, cJSON *json, const char *json_str);

typedef struct {
    ngx_peer_connection_t   peer;
    ngx_uint_t              usage;
    ngx_pool_t              *pool;
} ngx_http_redirectionio_resource_t;

typedef struct {
    ngx_http_redirectionio_resource_t               *resource;
    ngx_uint_t                                      matched_rule_status;
    const char                                      *matched_rule_str;
    cJSON                                           *matched_rule;

    const char                                      *filter_id;

    ngx_uint_t                                      connection_error;
    ngx_uint_t                                      wait_for_connection;

    ngx_uint_t                                      is_redirected;
    ngx_http_redirectionio_read_handler_t           read_handler;

    ngx_chain_t                                     *body_buffer;
    ngx_chain_t                                     *last_chain_sent;
} ngx_http_redirectionio_ctx_t;

void ngx_http_redirectionio_read_dummy_handler(ngx_event_t *rev, cJSON *json, const char *json_str);

ngx_int_t ngx_http_redirectionio_match_on_response_status_header_filter(ngx_http_request_t *r);
ngx_int_t ngx_http_redirectionio_headers_filter(ngx_http_request_t *r);

ngx_int_t ngx_http_redirectionio_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

ngx_http_output_header_filter_pt    ngx_http_next_header_filter;
ngx_http_output_body_filter_pt      ngx_http_next_body_filter;
ngx_module_t                        ngx_http_redirectionio_module;

ngx_int_t ngx_http_redirectionio_pool_construct(void **resource, void *params);
ngx_int_t ngx_http_redirectionio_pool_destruct(void *resource, void *params);
ngx_int_t ngx_http_redirectionio_pool_available(ngx_reslist_t *reslist, void *resource, void *data, ngx_int_t deferred);
ngx_int_t ngx_http_redirectionio_pool_available_log_handler(ngx_reslist_t *reslist, void *resource, void *data, ngx_int_t deferred);
void ngx_http_redirectionio_release_resource(ngx_reslist_t *reslist, ngx_http_redirectionio_ctx_t *ctx, ngx_uint_t in_error);
void ngx_http_redirectionio_read_handler(ngx_event_t *rev);

#endif
