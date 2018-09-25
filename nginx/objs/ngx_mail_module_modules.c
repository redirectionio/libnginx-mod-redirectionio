
#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_module_t  ngx_mail_module;
extern ngx_module_t  ngx_mail_core_module;
extern ngx_module_t  ngx_mail_ssl_module;
extern ngx_module_t  ngx_mail_pop3_module;
extern ngx_module_t  ngx_mail_imap_module;
extern ngx_module_t  ngx_mail_smtp_module;
extern ngx_module_t  ngx_mail_auth_http_module;
extern ngx_module_t  ngx_mail_proxy_module;

ngx_module_t *ngx_modules[] = {
    &ngx_mail_module,
    &ngx_mail_core_module,
    &ngx_mail_ssl_module,
    &ngx_mail_pop3_module,
    &ngx_mail_imap_module,
    &ngx_mail_smtp_module,
    &ngx_mail_auth_http_module,
    &ngx_mail_proxy_module,
    NULL
};

char *ngx_module_names[] = {
    "ngx_mail_module",
    "ngx_mail_core_module",
    "ngx_mail_ssl_module",
    "ngx_mail_pop3_module",
    "ngx_mail_imap_module",
    "ngx_mail_smtp_module",
    "ngx_mail_auth_http_module",
    "ngx_mail_proxy_module",
    NULL
};

char *ngx_module_order[] = {
    NULL
};

