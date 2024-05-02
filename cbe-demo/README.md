This folder contains demo web sites (`soc.ial`, `ebanksy.art`, `gall.ery`), hosting C2PA-signed content.

# Setup

Here are notes on how to self-host the demo on a Windows machine, deploying the `https://example.com` website in WSL (to this for each demo domains, replacing `example.com` with `soc.ial`, `ebanksy.art`, and `gall.ery`).

1. Install the [C2PA browser extension validator](https://github.com/microsoft/c2pa-extension-validator)
1. Install nginx in WSL
1. Generate a TLS cert using openssl
    * create a `openssl.cnf` file
        ```
        [ req ]
        distinguished_name = req_distinguished_name
                
        [req_distinguished_name]
                
        [ v3_issuer ]
        subjectAltName         = @alt_names
        subjectKeyIdentifier   = hash
        authorityKeyIdentifier = keyid:always
                
        [alt_names]
        DNS.1   = example.com
        DNS.2   = www.example.com
        ```			
    * run `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/example.com.key -out /etc/ssl/certs/example.com.crt -subj "/CN=example.com" -config openssl.cnf -extensions v3_issuer`
    * copy `/etc/ssl/certs/example.com.crt` somewhere in the windows partition
1. Install the TLS cert
    * Right-click on the `.crt` file and select "Install Certificate".
    * In the Certificate Import Wizard, select "Current User" and click "Next".
    * Select "Place all certificates in the following store".
    * Click "Browse", select "Trusted Root Certification Authorities", and click "OK".
    * Click "Next", then "Finish".
1. Setup the web site
    * run `sudo mkdir -p /var/www/example.com/html`
    * run `sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/example.com`
    * edit `/etc/nginx/sites-available/example.com`
        ```
            server {
                
                listen 443 ssl; # default_server;
                listen [::]:443 ssl; # default_server;
                ssl_certificate /etc/ssl/certs/example.com.crt;
                ssl_certificate_key /etc/ssl/private/example.com.key;
            
                root /var/www/example.com/html;
                index index.html;
            
                server_name example.com;
            
                location / {
                    try_files $uri $uri/ =404;
                }
            
                location /issue {
                    proxy_pass http://localhost:4000; # wherever the express server is
                    proxy_http_version 1.1;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection 'upgrade';
                    proxy_set_header Host $host;
                    proxy_cache_bypass $http_upgrade;
                }
            }
        ```	
    * run `sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/`
    * test the config, run `sudo nginx -t`
    * `sudo service nginx start` or `sudo service nginx reload`
* Update the hosts file (`C:\Windows\System32\drivers\etc\hosts`): 
    * `127.0.0.1 example.com`
* Demo-specific setup
    * Download file for "soc.ial" (in `soc.ial/html`) 
    * wget -O bbc.mp4 https://d2zo1lns8kb6p9.cloudfront.net/newslabs/origin/trial-01/cps/live-ugc-cps-68541911-2bbbc499-ef68-47aa-a9fb-7d281c2dff3e.mp4
    
## Run demo
1. Launch nginx: `sudo service nginx start`

## Ebanksy signed art

Ebanksy signed some images available in all demo domains. To (re-)generate these, following these steps (from the `ebanksy.art/c2pa` folder):

1. run `./generate-cert-chain.sh`. NOTE: the `c2patool` doesn't allow signing using a self-signed certificate, so the script generates a certificate chain.
1. generate a `trust-list.json` trust list file using the generated certs, and copy it to `ebanksy.art/html`.
1. sign the Ebanksy files: `c2patool <file> -m manifest-template.json -o <signed-file> -f`