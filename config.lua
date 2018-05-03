config = {
    registration = {
        termsOfServiceAgreed = true,
        contact = {"mailto:postmaster@example.net"}
    },

    -- ACME certificate authority configuration
    ca = {
        -- HAProxy backend which proxies requests to ACME server
        proxy_uri = "http://127.0.0.1:9012",
        -- ACME server URI (also returned by ACME directory listings)
        uri = "https://acme-v02.api.letsencrypt.org"
    }
}
