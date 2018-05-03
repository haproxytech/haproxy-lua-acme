Notes
=====

A few development notes and tips for HAProxy Lua ACME implementation.

RFCs
----

In addition to standard HTTP, JSON, TLS formats and protocols, knowledge of
other protocols/formats was necessary to develop ACME client.

* ACME protocol - https://tools.ietf.org/html/draft-ietf-acme-acme-09
* JWS (JSON Web Signature) - https://tools.ietf.org/html/rfc7515
* JWK (JSON Web Key) - https://tools.ietf.org/html/rfc7517

Tools
-----

Aside from `haproxy` and `curl`, additional software was used during
development, for testing and debugging.

Pebble
++++++

peble_ is a test ACME server with intented purpose to help with development of
ACME clients. It uses slightly different ACME endpoints than referent ACME
servers (all within specification), to force clients to properly implement
endpoint discovery. It also presents some other transient challenges to clients
(e.g. 15% of *nonces* are invalid), with the purpose of creating more robust
client implementations.

Server is a single binary, with configuration file in JSON format. By default
it includes a test CA infrastructure, and creates server side certificates on
the fly. There is also a simple acme client in the distribution,
`peble-client`, which can be used as a reference/starting point other clients.

Usage
~~~~~
After installing pebble, following their instructions, you can start it with:

::

  cd ~/go/src/github.com/letsencrypt/pebble
  ~/go/bin/pebble

It loads the configuration and certificates from `test` subdirectory, and binds
to port 14000 by default.


Boulder
+++++++

boulder_ is a reference ACME server, used by Let's Encrypt organization. One
can run it locally, via Docker Compose, for easier testing and validation.

MitmProxy
+++++++++

ACME protocol v2 mandates that clients use TLS to access the ACME server. That
means we can't easily track request flow from ACME client to server (e.g. to
debug our own client, or to observe `peble-client` behaviour). Unfortunately,
while `wireshark` can support/decrypt static SSL traffic, it doesn't support
Diffie-Hellman key exchanges, so decrypting standard TLS traffic is impossible.

mitmproxy_ is a TLS capable HTTP proxy for software developers and penetration
testers. We can use it to observe traffic between local ACME client and local
ACME server.

Usage
~~~~~

When you run peble it will create server key and cert in 
`~/go/src/github.com/letsencrypt/pebble/test/certs/localhost`. You need to
concat test key and cert into single file (`mitm.pem` in our example)

::

  sudo mitmweb -R https://localhost:14000 -p 443 --no-browser --insecure --cert localhost=~/go/src/github.com/letsencrypt/pebble/test/certs/localhost/mitm.pem
  Proxy server listening at http://0.0.0.0:443/
  Web   server listening at http://127.0.0.1:8081/

For the time being, it is necesarry to run mitmproxy with sudo, binding to port
443, even if we'd like to run it on some nonprivileged port, e.g. 8443

::

  sudo mitmweb -R https://localhost:14000 -p 8443 --no-browser --insecure --cert localhost=~/go/src/github.com/letsencrypt/pebble/test/certs/localhost/mitm.pem
  Proxy server listening at http://0.0.0.0:443/
  Web   server listening at http://127.0.0.1:8081/
   
When we run discovery query against the ACME server (through mitmproxy), we
get this:

::

  curl -k https://localhost:8443/dir 
  {
    "meta": {
      "termsOfService": "data:text/plain,Do%20what%20thou%20wilt"
     },
     "newAccount": "https://localhost/sign-me-up",
     "newNonce": "https://localhost/nonce-plz",
     "newOrder": "https://localhost/order-plz"
  }

were we'd expect to get 

::

  {
    "meta": {
      "termsOfService": "data:text/plain,Do%20what%20thou%20wilt"
     },
     "newAccount": "https://localhost:8443/sign-me-up",
     "newNonce": "https://localhost:8443/nonce-plz",
     "newOrder": "https://localhost:8443/order-plz"
  }

mitmproxy doesn't pass full host info to the upstream, i.e. it doesn't respect
HTTP 1.1 RFC (https://tools.ietf.org/html/rfc7230#section-5.4), where `Host`
header **must** include hostname and port if port is not 80 (for http) or 443
(for https). Hence, we force mitmproxy to run on standard HTTPS port, where
explicit port is not required.

.. _peble: https://github.com/letsencrypt/pebble
.. _boulder: https://github.com/letsencrypt/boulder
.. _mitmproxy: https://mitmproxy.org
