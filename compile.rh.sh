#!/bin/bash

set -e

#export NGINX_VERSION=`nginx -v 2>&1 | gawk 'match($0,/nginx version: nginx\/([0-9\.]+?)/,a) {print a[1]}'`
cp /root/clients/binaries/libredirectionio.h /usr/include/redirectionio.h
cp /root/clients/binaries/libredirectionio.so /usr/lib64/libredirectionio.so
chmod +x /usr/lib64/libredirectionio.so

./configure \
    --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' \
    --with-ld-opt=' -Wl,-E' \
    --with-debug \
    --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body \
    --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi \
    --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi \
    --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio \
    --with-ipv6 --with-http_auth_request_module --with-http_ssl_module --with-http_v2_module --with-http_realip_module \
    --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic \
    --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module \
    --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module \
    --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module \
    --with-http_stub_status_module --with-http_perl_module=dynamic --with-mail=dynamic --with-mail_ssl_module \
    --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module \
    --add-dynamic-module=../clients/nginx-redirectionio-module

make -j8 modules

mkdir -p /usr/share/nginx/modules

cp objs/ngx_http_redirectionio_module.so /root/clients/binaries/ngx_http_redirectionio_module.so
cp objs/ngx_http_redirectionio_module.so /usr/share/nginx/modules/ngx_http_redirectionio_module.so

exec nginx -t
