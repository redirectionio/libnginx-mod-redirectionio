#ifndef redirectionio_protocol_h
#define redirectionio_protocol_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_json.h>

typedef struct {
    ngx_chain_t         *input;
    ngx_chain_t         *output;
    ngx_http_request_t  *r;
} ngx_http_redirectionio_buffer_filtered_t;

typedef struct {
    ngx_str_t   project_key;
    ngx_str_t   uri;
    ngx_str_t   host;
    ngx_str_t   rule_id;
    ngx_int_t   status;
    ngx_str_t   location;
    ngx_str_t   user_agent;
    ngx_str_t   referer;
} ngx_http_redirectionio_log_t;

void ngx_http_redirectionio_protocol_send_match(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key);
void ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_redirectionio_log_t *log);
ngx_http_redirectionio_log_t* ngx_http_redirectionio_protocol_create_log(ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id);
void ngx_http_redirectionio_protocol_free_log(ngx_http_redirectionio_log_t *log);
void ngx_http_redirectionio_protocol_send_filter_header(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id);
void ngx_http_redirectionio_protocol_send_filter_body(ngx_connection_t *c, ngx_http_redirectionio_buffer_filtered_t *buffer, ngx_str_t *project_key, ngx_str_t *rule_id, ngx_uint_t is_first);

#endif
