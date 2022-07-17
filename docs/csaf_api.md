## csaf_api

### config options

The following options can be used in the config file in TOML format:

```
verbose             // Whether to print verbose output to stdout (default: "false")
bind_address        // The address with port, the API should listen to (default: "0.0.0.0:8080")
csaf_documents_path // The base path where all CSAF Documents are stored (default: "/var/www")
auth                // Array containing the tokens which can be specified in requests to access documents with higher TLP-Labels
auth.token          // The authentication token. This PoC uses Bearer Auth, so the Request Header looks like "Bearer <token>"
auth.allowed_tlp_labels  // The TLP-labels this token is eligable for, excluding the TLP:WHITE label
used_in             // Defines, in which CSAF component this API instance is used in (e.g. "csaf_trusted_provider")
```

#### Example config file
```toml
verbose = true
bind_address = "0.0.0.0:8081"
used_in = "csaf_trusted_provider"

[[auth]]
token = "abc123"
allowed_tlp_labels = ["GREEN"]

[[auth]]
token = "def456"
allowed_tlp_labels = ["GREEN", "AMBER", "RED"]
```

### nginx adjustments

The API endpoint itself does not handle TLS-Connections so it must be embedded under a seperate path with a reverse proxy.

Please read [provider-setup.md](provider-setup.md) first to setup nginx. Then add this location directive to your existing nginx config (`/etc/nginx/sites-available/default`):

```
server {
    ...
    location /.well-known/csaf/api/ {
        add_header Access-Control-Allow-Origin "*";
        proxy_pass http://localhost:8081/;
    }
    ...
}
```

This setting also allows CORS-Requests to the API endpoint from all origins.

### Adjustments for the provider or aggregator

The API endpoint must be exposed through the `provider-metadata.json`, or `aggregator.json` respectively. In order to do so, add this to your `config.toml` or `aggregator.toml`:

```toml
[api]
endpoint_url = "https://your.host/.well-known/csaf/api"
supported_versions = ["v1"]
```

Of course, the endpoint can be hosted on a different path or host, but it must match the settings made in nginx.