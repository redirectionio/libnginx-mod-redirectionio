#!/usr/bin/env bash

# this script is for developers only.
# dependent on the ngx-build script from the nginx-devel-utils repostory:
#   https://github.com/openresty/nginx-devel-utils/blob/master/ngx-build
# the resulting nginx is located at ./work/nginx/sbin/nginx
root=`pwd`
version=${1:-1.9.15}
home=~

# the ngx-build script is from https://github.com/openresty/openresty-devel-utils
            #--add-module=$home/work/nginx_upload_module-2.2.0 \
            #--without-pcre \
            #--without-http_rewrite_module \
            #--without-http_autoindex_module \
            #--with-cc=gcc46 \
            #--with-cc=clang \
            #--without-http_referer_module \
            #--with-http_spdy_module \

export NGX_BUILD_CC="gcc"
export NGX_BUILD_JOBS=8

echo `pwd`

ngx-build $version \
    --with-cc-opt="-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2" \
    --with-ld-opt="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC" \
    --with-debug \
    --with-pcre-jit \
    --with-ipv6 \
    --with-http_stub_status_module \
    --with-http_realip_module \
    --with-http_auth_request_module \
    --with-http_v2_module \
    --with-http_dav_module \
    --with-http_slice_module \
    --with-threads \
    --with-http_addition_module \
    --with-http_flv_module \
    --with-http_geoip_module=dynamic \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_image_filter_module=dynamic \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_sub_module \
    --with-http_xslt_module=dynamic \
    --with-mail=dynamic \
    --with-stream=dynamic \
    --add-module=/home/rio/clients/nginx-redirectionio-module \
    $opts \
    --with-debug
