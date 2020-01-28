FROM haproxy:2.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      lua-json \
      lua-luaossl \
 && apt-get clean
ENV CONFIG_DIR=/usr/local/etc/haproxy/
# lua http
RUN curl https://raw.githubusercontent.com/haproxytech/haproxy-lua-http/master/http.lua > /http.lua
# https://github.com/haproxytech/haproxy-lua-acme
RUN curl https://raw.githubusercontent.com/haproxytech/haproxy-lua-acme/master/acme.lua > /acme.lua \
 && curl https://raw.githubusercontent.com/haproxytech/haproxy-lua-acme/master/config.lua > /config.lua \
 && curl https://raw.githubusercontent.com/haproxytech/haproxy-lua-acme/master/haproxy.cfg > $CONFIG_DIR/haproxy.cfg
# check conf
RUN haproxy -c -- $CONFIG_DIR/haproxy.cfg

