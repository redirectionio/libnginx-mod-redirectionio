#include <ngx_http_redirectionio_protocol.h>

const char COMMAND_MATCH_NAME[] = "MATCH_WITH_RESPONSE";
const char COMMAND_MATCH_QUERY[] = "{ \"project_id\": \"%V\", \"request_uri\": \"%V\", \"host\": \"%V\" }";
const char COMMAND_LOG_NAME[] = "LOG";
const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%V\", \"request_uri\": \"%V\", \"host\": \"%V\", \"rule_id\": \"%V\", \"target\": \"%V\", \"status_code\": %d, \"user_agent\": \"%V\", \"referer\": \"%V\" }";
const char COMMAND_FILTER_HEADER_NAME[] = "FILTER_HEADER";
const char COMMAND_FILTER_BODY_NAME[] = "FILTER_BODY";

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

static void ngx_http_redirectionio_protocol_write_string(ngx_connection_t *c, u_char* data, uint64_t len);
static void ngx_str_copy(ngx_str_t *src, ngx_str_t *dest);

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

void ngx_http_redirectionio_protocol_send_log(ngx_connection_t *c, ngx_http_redirectionio_log_t *log) {
    ssize_t     wlen;
    u_char      *dst;
    ngx_str_t   v;

    wlen =
        sizeof(COMMAND_LOG_QUERY)
        + log->project_key.len
        + log->uri.len
        + log->host.len
        + log->rule_id.len
        + 3 // Status code length
        + log->location.len
        + log->user_agent.len
        + log->referer.len
        - 16 // 8 * 2 (%x) characters replaced with values
    ;

    dst = (u_char *) ngx_pcalloc(c->pool, wlen);

    ngx_sprintf(
        dst,
        COMMAND_LOG_QUERY,
        &log->project_key,
        &log->uri,
        &log->host,
        &log->rule_id,
        &log->location,
        log->status,
        &log->user_agent,
        &log->referer
    );

    v = (ngx_str_t) { wlen, dst };

    ngx_send(c, (u_char *)COMMAND_LOG_NAME, sizeof(COMMAND_LOG_NAME));
    ngx_send(c, v.data, v.len);
}

ngx_http_redirectionio_log_t* ngx_http_redirectionio_protocol_create_log(ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id) {
    ngx_http_redirectionio_log_t    *log = malloc(sizeof(ngx_http_redirectionio_log_t));
    ngx_memzero(log, sizeof(ngx_http_redirectionio_log_t));

    if (log == NULL) {
        return NULL;
    }

    ngx_str_copy(project_key, &log->project_key);
    ngx_str_copy(rule_id, &log->rule_id);
    ngx_str_copy(&r->unparsed_uri, &log->uri);

    log->user_agent = (ngx_str_t)ngx_null_string;
    log->referer = (ngx_str_t)ngx_null_string;
    log->host = (ngx_str_t)ngx_null_string;
    log->location = (ngx_str_t)ngx_null_string;
    log->status = r->headers_out.status;

    if (r->headers_in.user_agent != NULL) {
        ngx_str_copy(&r->headers_in.user_agent->value, &log->user_agent);
    }

    if (r->headers_in.referer != NULL) {
        ngx_str_copy(&r->headers_in.referer->value, &log->referer);
    }

    if (r->headers_in.host != NULL) {
        ngx_str_copy(&r->headers_in.host->value, &log->host);
    }

    if (r->headers_out.location != NULL) {
        ngx_str_copy(&r->headers_out.location->value, &log->location);
    }

    return log;
}

void ngx_http_redirectionio_protocol_free_log(ngx_http_redirectionio_log_t *log) {
    free(log->project_key.data);
    free(log->rule_id.data);
    free(log->uri.data);
    free(log->user_agent.data);
    free(log->referer.data);
    free(log->host.data);
    free(log->location.data);

    free(log);
}

void ngx_http_redirectionio_protocol_send_filter_header(ngx_connection_t *c, ngx_http_request_t *r, ngx_str_t *project_key, ngx_str_t *rule_id) {
    ssize_t             wlen;
    const char          *dst;
    ngx_str_t           v;
    ngx_str_t           encoded_headers = ngx_null_string;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_uint_t          i;
    cJSON               *query, *headers, *header;

    query = cJSON_CreateObject();
    headers = cJSON_CreateArray();

    cJSON_AddItemToObject(query, "project_id", cJSON_CreateString((const char *)project_key->data));
    cJSON_AddItemToObject(query, "rule_id", cJSON_CreateString((const char *)rule_id->data));
    cJSON_AddItemToObject(query, "headers", headers);

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        // Not used skip it
        if (h[i].hash == 0) {
            continue;
        }

        header = cJSON_CreateObject();
        cJSON_AddItemToObject(header, "name", cJSON_CreateString((const char *)h[i].key.data));
        cJSON_AddItemToObject(header, "value", cJSON_CreateString((const char *)h[i].value.data));

        cJSON_AddItemToArray(headers, header);
    }

    //@TODO Memory clean

    dst = cJSON_PrintUnformatted(query);

    ngx_send(c, (u_char *)COMMAND_FILTER_HEADER_NAME, sizeof(COMMAND_FILTER_HEADER_NAME));
    ngx_send(c, (u_char *)dst, ngx_strlen(dst) + 1);
}

void ngx_http_redirectionio_protocol_send_filter_body(ngx_connection_t *c, ngx_http_redirectionio_buffer_filtered_t *buffer, ngx_str_t *project_key, ngx_str_t *rule_id, ngx_uint_t is_first) {
    ngx_chain_t     *chain;
    ngx_uint_t      bsize;

    if (is_first) {
        // If first write command name
        ngx_send(c, (u_char *)COMMAND_FILTER_BODY_NAME, sizeof(COMMAND_FILTER_BODY_NAME));

        // If first write project id
        ngx_http_redirectionio_protocol_write_string(c, (u_char *)project_key->data, project_key->len);

        // If first write rule id
        ngx_http_redirectionio_protocol_write_string(c, (u_char *)rule_id->data, rule_id->len);
    }

    // Write buffer in only if buffer_size > 0
    chain = buffer->input;

    while (chain != NULL) {
        // Send buffer only if buffer_size > 0
        if (chain->buf != NULL) {
            bsize = ngx_buf_size(chain->buf);

            if (bsize > 0) {
                ngx_http_redirectionio_protocol_write_string(c, (u_char *)chain->buf->pos, bsize);
            }
        }

        if (chain->next == NULL) {
            break;
        }

        chain = chain->next;
    }

    // If last write empty buffer
    if (chain->buf != NULL && chain->buf->last_buf) {
        bsize = 0;

        ngx_send(c, (u_char *)&bsize, sizeof(bsize));
    }
}

static void ngx_str_copy(ngx_str_t *src, ngx_str_t *dest) {
    dest->len = src->len;
    dest->data = malloc(dest->len);
    ngx_memcpy(dest->data, src->data, dest->len);
}

static void ngx_http_redirectionio_protocol_write_string(ngx_connection_t *c, u_char* data, uint64_t len) {
    uint64_t size;
    ssize_t  sent;

    size = htonll(len);

    sent = ngx_send(c, (u_char *)&size, sizeof(uint64_t));
    sent = sent + ngx_send(c, data, len);
}
