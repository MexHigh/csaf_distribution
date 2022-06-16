## csaf_api

### config options

The following options can be used in the config file in TOML format:

```
bind_address // The address with port, the API should listen to (default: "0.0.0.0:8080")
```

#### Example config file
```toml
bind_address = "0.0.0.0:1234"
```

### nginx adjustments

The API endpoint itself does not handle TLS-Connections so it must be embedded under a seperate path with a reverse proxy.

Please read [provider-setup.md](provider-setup.md) first to setup nginx. Then add this location directive to your existing nginx config (`/etc/nginx/sites-available/default`):

```
server {
    ...
    location /.well-known/csaf/api/ {
		proxy_pass http://localhost:8080;
	}
    ...
}
```

**Documentation pending**