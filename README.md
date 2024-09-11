Champa – general-purpose proxy through an AMP cache
David Fifield <david@bamsoftware.com>
Public domain


Champa is a pair of programs—champa-client and champa-server—that
implements a proxy tunnel over an AMP cache, with the goal of
circumventing Internet censorship. It is not limited to tunneling HTTP;
it encodes data into HTTP requests that satisfy the requirements of AMP.

AMP ("Accelerated Mobile Pages") is a framework for mobile web pages.
AMP pages are written in a restricted subset of HTML. An
[AMP cache](https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/how_amp_pages_are_cached/)
is a cache and proxy for AMP HTML pages: it forwards HTTP requests from
a client to an origin server, and relays HTTP responses back to the
client, while enforcing the requirement that responses be written in AMP
HTML. Champa transforms a specialized AMP cache proxy into a
general-purpose proxy.

Access through an AMP cache normally exposes the domain name of the
origin server in the hostname of the URL by which the cache is accessed.
To hide the origin server from an observer, the champa-client supports
domain fronting to make it appear to an external observer that you are
accessing a different domain. When you run champa-client, you provide
both the URL of an AMP cache

As of 2021, there is really only one option for an AMP cache,
[Google AMP Cache](https://developers.google.com/amp/cache/) at
https://cdn.ampproject.org/. When you run champa-client, you will
therefore always use the `-cache https://cdn.ampproject.org/` option,
along with a `-front` option specifying a Google domain for domain
fronting.

Champa is an application-layer tunnel that runs in userspace. It doesn't
provide a TUN/TAP interface; it only connects a local TCP port to a
remote TCP port by way of an AMP cache tunnel DNS resolver. It does not
itself provide a SOCKS or HTTP proxy interface, but you can get the same
effect by running a proxy on the tunnel server and having the tunnel
forward to the proxy.


## Tunnel server

The server end of the tunnel must be run on a publicly accessible
server, outside the censor's zone of control. champa-server is a
plaintext HTTP server. It is meant to listen on localhost, behind a
reverse web proxy that can provide TLS to incoming traffic, such as
Apache or Nginx.

Compile champa-server:
```
tunnel-server$ cd champa-server
tunnel-server$ go build
```

Generate a keypair that will be used for end-to-end confidentiality and
integrity with tunnel clients. The server needs to keep a copy of the
private key. Each clients needs a copy of the public key.
```
tunnel-server$ ./champa-server -gen-key -privkey-file server.key -pubkey-file server.pub
privkey written to server.key
pubkey  written to server.pub
```

Run champa-server. In this example `127.0.0.1:8080` is the port that the
HTTP server will listen on. `127.0.0.1:7001` is the TCP address to which
incoming tunneled connection will be forwarded—this can be a proxy
server, for example.
```
tunnel-server$ ./champa-server -privkey-file server.key 127.0.0.1:8080 127.0.0.1:7001
```

Next, you need to configure a reverse web proxy to connect
champa-server's HTTP port to the outside world. Below are instructions
for how to do this using Apache and Nginx on Debian. The examples assume
that you have already installed a web server and configured it to answer
requests for the domain example.com. Clients will access the server at
the URL `https://example.com/champa/` (through an AMP cache).


### Apache reverse proxy

For general information on configuring a reverse proxy with Apache, see
https://httpd.apache.org/docs/current/howto/reverse_proxy.html#simple.

Configure the server to use TLS, if it does not already. You can do this
using Certbot:
```
tunnel-server$ apt install python3-certbot-apache
tunnel-server$ certbot
```

Enable the proxy_http Apache module. Although not required, you probably
also want to enable the http2 module.
```
tunnel-server$ a2enmod proxy_http http2
```

Find the `<VirtualHost>` directive, and add a new `<Location>` directive
with the path prefix you want to reserve for Champa traffic (here,
`"/champa/"`). Add `ProxyPass` and `ProxyPassReverse` directives
pointing to champa-server's HTTP listening port. You may also want to
disable logging for requests under the path prefix.
```
<VirtualHost *:443>
	ServerName example.com
	<Location "/champa/">
		ProxyPass http://127.0.0.1:8080/
		ProxyPassReverse http://127.0.0.1:8080/
		SetEnv nolog
	</Location>
	CustomLog ${APACHE_LOG_DIR}/access.log combined env=!nolog
</VirtualHost>
```

Restart Apache:
```
tunnel-server$ apache2ctl restart
```


### Nginx reverse proxy

For general information on configuring a reverse proxy with Nginx, see
https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/#passing-a-request-to-a-proxied-server.

Configure the server to use TLS, if it does not already. You can do this
using Certbot:
```
tunnel-server$ apt install python3-certbot-nginx
tunnel-server$ certbot
```

Find the `server` directive, and add a new `location` directive with the
path prefix you want to reserve for Champa traffic (here, `/champa/`).
Add a `proxy_pass` directive pointing to champa-server's HTTP listening
port. The trailing slash in the URL after `proxy_pass` is important. You
may also want to disable logging for requests under the path prefix. Add
`http2` to the `listen` directives, if it is not there already.
```
server {
	server_name example.com;
	location /champa/ {
		proxy_pass http://127.0.0.1:8080/;
		proxy_redirect default;
		access_log off;
	}
	listen [::]:443 ssl http2 ipv6only=on; # managed by Certbot
	listen 443 ssl http2; # managed by Certbot
}
```

Restart Nginx:
```
tunnel-server$ nginx -s reload
```


## Tunnel client

Compile champa-client:
```
tunnel-client$ cd champa-client
tunnel-client$ go build
```

Copy the server's public key (server.pub) to the client. You don't need
the private key (server.key) on the client.

Run champa-client.
```
tunnel-client$ ./champa-client -pubkey-file server.pub -cache https://cdn.ampproject.org/ -front www.google.com https://example.com/champa/ 127.0.0.1:7000
```

The champa-client command line requires five pieces of information:
* `-pubkey-file server.pub`
  The server's public key.
* `-cache https://cdn.ampproject.org/`
  The URL of the AMP cache to proxy through.
* `-front www.google.com`
  The externally visible domain name to use when connecting to the AMP
  cache. You can use a Google-operated domain here.
* `https://example.com/champa/`
  The URL of the tunnel server.
* `127.0.0.1:7000`
  The local TCP port that will receive connections and forward them
  through the tunnel.

In this example, connections to 127.0.0.1:7000 on the tunnel client
will be tunneled through the AMP cache at https://cdn.ampproject.org/
with www.google.com as a domain front, arriving at the tunnel server at
https://example.com/champa/, which will then forward the tunneled
connections to its own 127.0.0.1:7001.


## How to make a proxy

Champa is only a tunnel: it connects a local TCP port to a remote TCP
port in a hard-to-detect way. What you connect to those ports is your
choice, but generally it will be some kind of proxy.


### Ncat HTTP proxy

[Ncat](https://nmap.org/ncat/) has a simple built-in HTTP/HTTPS proxy,
good for testing. Be aware that Ncat's proxy isn't intended for use by
untrusted clients; it won't prevent them from connecting to localhost
ports on the tunnel server, for example.

```
tunnel-server$ ncat -l -k --proxy-type http 127.0.0.1 7001
tunnel-server$ ./champa-server -privkey-file server.key 127.0.0.1:8080 127.0.0.1:7001
```

On the client, have the tunnel client listen on 127.0.0.1:7000, and
configure your applications to use 127.0.0.1:7000 as an HTTP proxy.

```
tunnel-client$ ./champa-client -pubkey-file server.pub -cache https://cdn.ampproject.org/ -front www.google.com https://example.com/champa/ 127.0.0.1:7000
tunnel-client$ curl --proxy http://127.0.0.1:7000/ https://wtfismyip.com/text
```
