--
-- acme.lua
--
-- ACME v2 protocol client implementation for HAProxy Lua host
--
-- ACME RFC:
-- https://tools.ietf.org/html/draft-ietf-acme-acme-12
--
-- Copyright (c) 2017-2018. Adis Nezirovic <anezirovic@haproxy.com>
-- Copyright (c) 2017-2018. HAProxy Technologies, LLC.
-- All rights reserved

local _author = "Adis Nezirovic <anezirovic@haproxy.com>"
local _copyright = "Copyright 2017-2018. HAProxy Technologies, LLC. All Rights Reserved."
local _version = "1.0.0"

local http = require "http"
local json = require "json"

local openssl = {
    pkey = require "openssl.pkey",
    x509 = require "openssl.x509",
    name = require "openssl.x509.name",
    altname = require "openssl.x509.altname",
    csr = require "openssl.x509.csr",
    digest = require "openssl.digest"
}

if not config then
    config = {
        -- ACME certificate authority configuration
        ca = {
            -- HAProxy backend which proxies requests to ACME server
            proxy_uri = "http://127.0.0.1:9012",
            -- ACME server URI (also returned by ACME directory listings)
            uri = "https://acme-v02.api.letsencrypt.org"
        },

        registration = {
            termsOfServiceAgreed = false,
            contact = {"mailto:user@example.net"}
        }
    }
end

-- Storage area for serving challanges to ACME server
local http_challenges = {}

local ACME = {}
ACME.__index = ACME

function ACME.create(conf)
    local self = setmetatable({}, ACME)

    self.conf = conf or {}

    -- ACME resources, only 'directory' resource should be known in advance
    self.resources = nil

    local resp
    local err

    for _, d in ipairs({"/directory", "/dir", "/"}) do
        resp, err = http.get{url=config.ca.proxy_uri .. d}

        if resp and resp.status_code == 200 and resp.headers["content-type"]
                and resp.headers["content-type"]:match("application/json") then
            self.resources = json.decode(resp.content)
            self.nonce = resp.headers["replay-nonce"]
            break
        end
    end

    if not self.resources then
        return nil, err
    end

    assert(self.resources["newNonce"])
    assert(self.resources["newAccount"])
    assert(self.resources["newOrder"])
    assert(self.resources["revokeCert"])

    self.account = {
        key = nil,
        kid = nil
    }

    return self
end

--- Adapt resource URLs when going through HAProxy
function ACME.proxy_url(self, url)

    if url:sub(1, #self.conf.ca.uri) == self.conf.ca.uri then
        return string.format("%s%s", self.conf.ca.proxy_uri, url:sub(#self.conf.ca.uri))
    else
        return url
    end
end

--- ACME wrapper for http.post()
--
-- @param resource  ACME resource type
-- @param url       Valid HTTP url (mandatory)G
-- @param headers   Lua table with request headers
-- @param data      Request content
--
-- @return Response object or tuple (nil, msg) on errors
function ACME.post(self, t)
    local jws, err = self:jws{resource=t.resource, url=t.url, payload=t.data}

    if not jws then
        return nil, err
    end

    if not t.headers then
        t.headers = {
            ["content-type"] = "application/jose+json"
        }
    elseif not t.headers["content-type"] then
        t.headers["content-type"] = "application/jose+json"
    end

    local resp, err = http.post{url=self:proxy_url(t.url), data=jws,
                                headers=t.headers, timeout=t.timeout}
    if resp and resp.headers then
        self.nonce = resp.headers["replay-nonce"]

        if resp.status_code == 400 then
            local info = resp:json()

            if info and info.type == "urn:ietf:params:acme:error:badNonce" then

                -- We need to retry once more with new nonce (hence new jws)
                jws, err = self:jws{resource=t.resource, url=t.url,
                                    payload=t.data}
                if not jws then
                    return nil, err
                end

                resp, err = http.post{url=self:proxy_url(t.url), data=jws,
                                      headers=t.headers}
            end
        end
    end

    return resp, err
end

--- Return the ACME nonce
--
-- Nonce is volatile, if nonce is not present (i.e.from previous request),
-- a fresh nonce is requested from the ACME server, otherwise, the stored
-- nonce is returned (and deleted)
--
function ACME.refresh_nonce(self)
    local nonce = self.nonce
    self.nonce = nil
    if nonce then return nonce end


    local r, e = http.head{url=self:proxy_url(self.resources["newNonce"])}

    if r and r.headers then
        -- TODO: Expect status code 204
        -- TODO: Expect Cache-Control: no-store
        -- TODO: Expect content size 0
        return r.headers["replay-nonce"]
    else
        return nil, e
    end
end

--- Enclose the provided payload in JWS
--
-- @param url       URL
-- @param resource  ACME resource type
-- @param payload   (json) data which will be wrapped in JWS
function ACME.jws(self, t)
    if not self.account or not self.account.key then
        return nil, "ACME.jws: Account key does not exist."
    end

    if not t or not t.resource or not t.url or not t.payload then
        return nil,
            "ACME.jws: Missing one or more parameters (resource, url, payload)"
    end

    -- if key:type() == rsaEncryption
    local params = self.account.key:getParameters()
    if not params then
        return nil, "ACME.jws: Could not extract account key parameters."
    end

    local jws = {
        protected = {
            alg = "RS256",
            nonce = self:refresh_nonce(),
            url = t.url
        },
        payload = t.payload
    }

    if t.resource == "newAccount" then
        -- if self.account.key:type() == "rsaEncryption" then
        jws.protected.jwk = {
            e = http.base64.encode(params.e:toBinary(), base64enc),
            kty = "RSA",
            n = http.base64.encode(params.n:toBinary(), base64enc)
        }

        local jwk_ordered = string.format('{"e":"%s","kty":"%s","n":"%s"}',
                                          jws.protected.jwk.e,
                                          jws.protected.jwk.kty,
                                          jws.protected.jwk.n)
        local tdigest = openssl.digest.new("SHA256"):final(jwk_ordered)
        self.account.thumbprint = http.base64.encode(tdigest, base64enc)
    else
        jws.protected.kid = self.account.kid
    end

    jws.protected = http.base64.encode(json.encode(jws.protected), base64enc)
    jws.payload = http.base64.encode(json.encode(t.payload), base64enc)
    local digest = openssl.digest.new("SHA256")
    digest:update(jws.protected .. "." .. jws.payload)
    jws.signature = http.base64.encode(self.account.key:sign(digest), base64enc)

    return json.encode(jws)
end

function ACME.register(self)
    if not self.account then
        return nil, 'No account key'
    end

    local resp, err = self:post{url=self.resources["newAccount"],
                                data=self.conf.registration,
                                resource="newAccount"}

    if not resp then
        return nil, err
    end

    self.account.kid = resp.headers['location']

    return resp
end

local function new_order(applet)
    local acme, err = ACME.create(config)

    if not acme then
        return http.response.create{status_code=500, content=err}:send(applet)
    end

    function base64enc(s)
        return applet.c:base64(s)
    end

    function base64dec(s)
        -- Depends on HAProxy v1.8
        return applet.c:b64dec(s)
    end

    local r = http.request.parse(applet)

    if not (r and r.data) then
        return http.response.create{status_code=400, content=err}:send(applet)
    end

    local form, err = r:parse_multipart()

    if not form then
        return http.response.create{status_code=400, content=err}:send(applet)
    end

    if not (form.account_key and form.domain_key and form.domain) then
        local err = 'Missing one of mandatory form fields: account_key, domain, domain_key'
        return http.response.create{status_code=400, content=err}:send(applet)
    end

    acme.account = {
        key = openssl.pkey.new(form.account_key.data or form.account_key)
    }

    local resp, err = acme:register()

    if not resp then
        return http.response.create{status_code=500, data=err}:send(applet)
    end

    local aliases = {}
    if form.aliases then
        aliases = core.tokenize(form.aliases, ",")
    end

    local order_payload = {
        identifiers = {
            [1] = {
                type = "dns",
                value = form.domain
            }
        }
    }

    for idx, alias in pairs(aliases) do
        order_payload.identifiers[idx+1] = {type = "dns", value = alias}
    end

    -- Place new order
    resp, err = acme:post{url=acme.resources["newOrder"], data=order_payload,
                          resource="newOrder"}
    if not resp then
        return http.response.create{status_code=500, data=err}:send(applet)
    end

        -- if resp.code == 201
        local resp_json = resp:json()
        local finalize = resp_json.finalize
        local authorizations = resp_json.authorizations

        for _, auth in ipairs(authorizations) do
            --
            local auth_payload = {
                keyAuthorization = nil
            }

            -- Get auth token
            local resp, err = http.get{url=acme:proxy_url(auth)}

            if resp then
                local auth_resp = resp:json()

                for _, ch in ipairs(auth_resp.challenges) do
                    if ch.type == "http-01" then
                        http_challenges[ch.token] = string.format("%s.%s",
                            ch.token, acme.account.thumbprint)
                        resp, err = acme:post{url=ch.url, data=ch, resource="challengeDone", timeout=1}
                    end
                end
            end
        end

        -- TODO: Check pending status in a loop
        core.sleep(5)

        -- CSR creation
        local dn = openssl.name.new()
        dn:add("CN", form.domain)

        local alt = openssl.altname.new()
        alt:add("DNS", form.domain)

        for _, alias in pairs(aliases) do
            alt:add("DNS", alias)
        end

        local csr = openssl.csr.new()
        csr:setSubject(dn)
        csr:setSubjectAlt(alt)

        local key = openssl.pkey.new(form.domain_key.data or form.domain_key)
        csr:setPublicKey(key)
        csr:sign(key)
        local payload = {
            csr = http.base64.encode(csr:tostring("DER"), base64enc)
        }

        resp, err = acme:post{url=finalize, data=payload, resource="finalizeOrder"}

        if resp and resp.status_code == 200 then
            local resp_json = resp:json()

            if not resp_json.certificate then
                return http.response.create{status_code=500, content="No cert"}:send(applet)
            end

            local resp, err = http.get{url=acme:proxy_url(resp_json.certificate)}
            local bundle = string.format("%s%s", resp.content, key:toPEM("private"))
            return http.response.create{status_code=200, content=bundle}:send(applet)
        else
            return resp:send(applet)
        end
end

local function acme_challenge(applet)
    local p = core.tokenize(applet.path, "/", true)
    if not p[3] or not http_challenges[p[3]] then
        http.response.create{status_code=404}:send(applet)
    end
    http.response.create{status_code=200, content=http_challenges[p[3]]}:send(applet)
    http_challenges[p[3]] = nil
end

--- Request handler/router
--
--
local function request_handler(applet)
    local p = core.tokenize(applet.path, "/", true)
    local m = applet.method
    local h = {
        acme = {
            order = {
                POST = new_order
            }
        },
        [".well-known"] = {
            ["acme-challenge"] = {
                GET = acme_challenge
            }
        }
    }

    if h[p[1]] and h[p[1]][p[2]] and h[p[1]][p[2]][m] then
          return h[p[1]][p[2]][m]
    end

    return nil
end

local function main(applet)
    local handler = request_handler(applet)

    if not handler then
        http.response.create{status_code=404}:send(applet)
    else
        handler(applet)
    end
end

core.register_service("acme", "http", main)
