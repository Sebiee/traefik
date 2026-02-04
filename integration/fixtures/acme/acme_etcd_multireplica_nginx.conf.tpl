events {
    worker_connections 1024;
}

stream {
    upstream traefik_http {
        {{range .HTTPPorts}}
        server host.docker.internal:{{ . }};
        {{end}}
    }

    upstream traefik_https {
        {{range .HTTPSPorts}}
        server host.docker.internal:{{ . }};
        {{end}}
    }

    server {
        listen {{ .LBHTTPPort }};
        proxy_pass traefik_http;
    }

    server {
        listen {{ .LBHTTPSPort }};
        proxy_pass traefik_https;
    }
}
