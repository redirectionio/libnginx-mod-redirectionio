#!/bin/bash

set -e

#export NGINX_VERSION=`nginx -v 2>&1 | gawk 'match($0,/nginx version: nginx\/([0-9\.]+?)/,a) {print a[1]}'`
cp /root/clients/binaries/libredirectionio.so /usr/lib/libredirectionio.so

chmod +x /usr/lib/libredirectionio.so

./configure \
    --with-cc-opt='-g -O2 -fPIC -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
    --with-ld-opt='-Wl,-Bsymbolic-functions -fPIC -pie -Wl,-z,relro -Wl,-z,now' \
    --prefix=/usr/share/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --http-log-path=/var/log/nginx/access.log \
    --error-log-path=/var/log/nginx/error.log \
    --lock-path=/var/lock/nginx.lock \
    --pid-path=/run/nginx.pid \
    --http-client-body-temp-path=/var/lib/nginx/body \
    --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
    --http-proxy-temp-path=/var/lib/nginx/proxy \
    --http-scgi-temp-path=/var/lib/nginx/scgi \
    --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
    --with-debug --with-pcre-jit --with-ipv6 \
    --with-http_ssl_module --with-http_stub_status_module \
    --with-http_realip_module --with-http_auth_request_module \
    --with-http_addition_module --with-http_dav_module --with-http_geoip_module \
    --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module \
    --with-http_v2_module --with-http_sub_module --with-http_xslt_module --with-stream \
    --with-stream_ssl_module --with-mail --with-mail_ssl_module --with-threads \
    --add-dynamic-module=../clients/nginx-redirectionio-module

make -j8 modules

mkdir -p /usr/share/nginx/modules

cp objs/ngx_http_redirectionio_module.so /root/clients/binaries/ngx_http_redirectionio_module.so
cp objs/ngx_http_redirectionio_module.so /usr/share/nginx/modules/ngx_http_redirectionio_module.so

nginx -t
