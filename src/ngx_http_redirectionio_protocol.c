#include <ngx_http_redirectionio_protocol.h>

const char COMMAND_MATCH_NAME[] = "MATCH";
const char COMMAND_MATCH_QUERY[] = "{ \"project_id\": \"%V\", \"request_uri\": \"%V\", \"host\": \"%V\" }";
const char COMMAND_LOG_NAME[] = "LOG";
const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%V\", \"request_uri\": \"%V\", \"host\": \"%V\", \"rule_id\": \"%V\", \"target\": \"%V\", \"status_code\": %d, \"user_agent\": \"%V\", \"referer\": \"%V\" }";

void ngx_http_redirectionio_protocol_send_match(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key) {
    ssize_t     wlen;
    u_char      *dst;
    ngx_str_t   v;
    ngx_str_t   host = ngx_null_string;

    if (r->headers_in.host != NULL) {
        host.data = r->headers_in.host->value.data;
        host.len = r->headers_in.host->value.len;
    }

    wlen = sizeof(COMMAND_MATCH_QUERY) + project_key->len + r->unparsed_uri.len + host.len - 6;
    dst = (u_char *) ngx_pcalloc(c->pool, wlen);
    ngx_sprintf(dst, COMMAND_MATCH_QUERY, project_key, &r->unparsed_uri, &host);
    v = (ngx_str_t) { wlen, dst };

    ngx_send(c, (u_char *)COMMAND_MATCH_NAME, sizeof(COMMAND_MATCH_NAME));
    ngx_send(c, v.data, v.len);
}

void ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id) {
    ssize_t     wlen;
    u_char      *dst;
    ngx_str_t   v;
    ngx_str_t   user_agent = ngx_null_string;
    ngx_str_t   referer = ngx_null_string;
    ngx_str_t   location = ngx_null_string;
    ngx_str_t   host = ngx_null_string;

    if (r->headers_in.user_agent != NULL) {
        user_agent.data = r->headers_in.user_agent->value.data;
        user_agent.len = r->headers_in.user_agent->value.len;
    }

    if (r->headers_in.referer != NULL) {
        referer.data = r->headers_in.referer->value.data;
        referer.len = r->headers_in.referer->value.len;
    }

    if (r->headers_in.host != NULL) {
        host.data = r->headers_in.host->value.data;
        host.len = r->headers_in.host->value.len;
    }

    if (r->headers_out.location != NULL) {
        location.data = r->headers_out.location->value.data;
        location.len = r->headers_out.location->value.len;
    }

    wlen =
        sizeof(COMMAND_LOG_QUERY)
        + project_key->len
        + r->unparsed_uri.len
        + host.len
        + rule_id->len
        + 3 // Status code length
        + location.len
        + user_agent.len
        + referer.len
        - 16 // 8 * 2 (%x) characters replaced with values
    ;

    dst = (u_char *) ngx_pcalloc(c->pool, wlen);

    ngx_sprintf(
        dst,
        COMMAND_LOG_QUERY,
        project_key,
        &r->unparsed_uri,
        &host,
        rule_id,
        &location,
        r->headers_out.status,
        &user_agent,
        &referer
    );

    v = (ngx_str_t) { wlen, dst };

    ngx_send(c, (u_char *)COMMAND_LOG_NAME, sizeof(COMMAND_LOG_NAME));
    ngx_send(c, v.data, v.len);
}
