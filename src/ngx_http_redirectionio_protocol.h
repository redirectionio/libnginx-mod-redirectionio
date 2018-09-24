#ifndef redirectionio_protocol_h
#define redirectionio_protocol_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

void ngx_http_redirectionio_protocol_send_match(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key);
void ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id);

#endif
