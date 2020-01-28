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
ADD acme.lua /acme.lua
ADD config.lua /config.lua
ADD haproxy.cfg $CONFIG_DIR/haproxy.cfg
# check conf
RUN haproxy -c -- $CONFIG_DIR/haproxy.cfg

