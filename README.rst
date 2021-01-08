HAProxy ACME v2 client
======================

Important notice
----------------
Beware, the fixes to support for ACME v2 protocol were recently merged, there
might be some sharp edges but it should work.

This is a client implementation for ACME (Automatic Certificate Management
Environment) protocol, currently draft IETF standard
(https://tools.ietf.org/html/draft-ietf-acme-acme-12)

The protocol will be supported by Let's Encrypt project from March 2018.
and it is expected that other *Certificate Authorities* will support this
ACME version in the future.

Intro
-----
The main idea of this ACME client is to implement as much functionality inside
HAProxy. In addition to supporting single instance HAProxy installations, we
also aim to support multi-instance deployments (i.e. you have a cluster of load
balancers on which you want to use ACME issued certs).

By using the internal HTTP interface (and http client such as `curl`), you will
be able to execute the following:

- Upload your own account and domain keys (only RSA keys for now)
- Automatically register your account on ACME servers (linked to your account
  key)
- Request and receive certificates for your domains

The only thing you need to do on your own is to save the received certificate
bundles and reload HAProxy.


Requirements
------------

* A modern HAProxy version (v1.8) with Lua support (check with
  ``haproxy -vv | grep USE_LUA=1``)
* `haproxy-lua-http`_ - Lua HTTP server/client for HAProxy Lua host
* `json.lua`_ - Lua JSON library
* `luaossl`_ - OpenSSL bindings for Lua


Configuration
-------------

Install the required Lua libraries to proper LUA_PATH location, and configure
haproxy as follows:

::

  global
      log /dev/log local0 debug
      nbproc 1
      daemon
      lua-load config.lua
      lua-load acme.lua

  defaults
      log global
      mode http
      option httplog
      timeout connect 5s
      timeout client 10s
      timeout server 10s

  listen http
      bind *:80
      http-request use-service lua.acme if { path_beg /.well-known/acme-challenge/  }

  listen acme
      bind 127.0.0.1:9011
      http-request use-service lua.acme

  listen acme-ca
    bind 127.0.0.1:9012
    server ca acme-v02.api.letsencrypt.org:443 ssl verify required ca-file letsencrypt-x3-ca-chain.pem
    http-request set-header Host acme-v02.api.letsencrypt.org

``letsencrypt-x3-ca-chain.pem`` is the concatenation of the active root certificate and intermediate certificate in one pem file, available here : https://letsencrypt.org/certificates/

Configuration is kept in a separate Lua file, where you must explicitly set
``termsOfServiceAgreed`` option to ``true`` in order to be able to acquire
certs. Before doing that, please read latest Let's Encrypt terms of service and
subscriber agreement available at https://letsencrypt.org/repository/

::

  config = {
      registration = {
          -- You can read TOS here: https://letsencrypt.org/repository/
          termsOfServiceAgreed = false,
          contact = {"mailto:postmaster@example.net"}
      },

      -- ACME certificate authority configuration
      ca = {
          -- HAProxy backend/server which proxies requests to ACME server
          proxy_uri = "http://127.0.0.1:9012",
          -- ACME server URI (also returned by ACME directory listings)
          -- Use this server name in HAProxy config
          uri = "https://acme-v02.api.letsencrypt.org",
      }
  }

Key creation
------------

Although Lua module is able to create account key or domain automatically, for
performance and security reasons we require that you create your keys
separately.

Currently, we only support RSA keys. For account key, key size should be
4096bits, and for domain key 2048bits (minimal key sizes are also enforced by
Let's Encrypt).

You can use the following commands to create keys. Note that you need a modern
openssl version, we don't use ``openssl genrsa`` but ``openssl genpkey``, as
we're going to use the same command to create ECDSA keys in the future.

::

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out account.key
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out example.net.key


Usage
-----

After you have provisioned your keys, you can run certificate order via HTTP.
For example by using curl to POST data in *multipart/form-data* format:

::

  curl -XPOST http://127.0.0.1:9011/acme/order -F 'account_key=@account.key' \
       -F 'domain=example.net' -F 'domain_key=@example.net.key' \
       -F 'aliases=www.example.net,example.com,www.example.com' \
       -o example.net.pem

Aliases are optional, and we use curl ``@`` syntax to post files.
The output is full certificate chain (with key appended), suitable for direct
consumption by HAProxy.

.. _`haproxy-lua-http`: https://github.com/haproxytech/haproxy-lua-http
.. _`json.lua`: https://github.com/rxi/json.lua
.. _`luaossl`: https://github.com/wahern/luaossl
