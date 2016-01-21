# captivedns
Flexible captive DNS server

A simple DNS server that responds with false results depending on certain factors. Example;

A perfectly normal A record lookup of facebook.com:

```
$ dig +short A facebook.com @10.0.0.6
173.252.120.68
```

Same lookup against the captivedns server:

```
$ dig +short A facebook.com @10.0.0.5
10.0.0.1
10.0.0.2
```
In the case above, the captivedns server was configured to respond to all A record lookup requests for facebook.com with IP addresses 10.0.0.1 and 10.0.0.2.

## Running

Currently, the server has *not* been packaged and there are no start-up scripts available (it's on my TODO list), so you'll have to do it the old-fashioned way using _nohup_. Example;

```
$ cd ~/captivedns
$ source virtualenv/bin/activate
$ nohup sudo virtualenv/bin/python dns_server.py --config dns-config.json &
```

## Config

The configuration for captivedns is held in a JSON-encoded file. Example:

```json
{
  "bind-ip": "10.172.254.182",
  "ttl": 30,
  "resolv-conf": "/etc/resolv.conf",

  "default-a-records": ["10.0.0.1", "10.0.0.2"],
  "default-ptr-records": ["portal.local."],

  "log-level": "debug",
  "log-file": "./captive-dns-server.log",

  "auth-plugin": {
    "type": "ACLAuth",
    "action": "DENY",
    "acls":
            [
              "(?:.*\\.)?facebook.com",
              "pornhub",
              "4chan",
              "1.0.0.10.in-addr.arpa"
            ]
  }
}
```

* _bind-ip_ - The IP address to bind to.
* _ttl_ - DNS record time-to-live. Read https://en.wikipedia.org/wiki/Time_to_live#DNS_records
* _resolve-conf_ - Path to file containing list of name servers to use for DNS lookups.
* _default-a-records_ - List of IP addresses to respond with in place of actual A records.
* _default-ptr-records_ - List of names to respond with in place of actual PTR records.
* _log-file_ - The log file to write to.
* _auth-plugin_ - Which auth plugin is to be used. The value of this key will contain the name and configuration of the plugin.

## Auth Plugins

The captivedns server has the concept of "auth plugins" - bits of logic that decide if the server should respond with a false response. Right now the following plugins are supported:

* _AlwaysRedirect_ - Always respond with false record(s).
* _NeverRedirect_ - Do not respond with false record(s) at all.
* _SimpleWebAuth_ - Make an HTTP(s) call to a URL that will determine if a false response should be sent.
* _ACLAuth_ - Send a false response if the domain matches any of the given regular expressions.

#### AlwaysRedirect
```
auth-plugin": {
    "type": "AlwaysRedirect"
  }

```

#### NeverRedirect
```
auth-plugin": {
    "type": "NeverRedirect"
  }

```

#### SimpleWebAuth
```
 "auth-plugin": {
    "type": "SimpleWebAuth",
    "url": "http://localhost/check_ip.php",
    "method": "GET",
    "expect-code": 200,
    "expect-string": "OK"
  }
```

* _url_ - the URL to call. The following query parameters are passed along:
  * source_ip - the client IP address
  * query_type - the type of DNS query being done; A, PTR, etc.
  * query_name - the host/domain/IP address needing to be looked up.
* _method_ - the HTTP method to use: GET, POST, etc.
* _expect-code_ - the HTTP response code to expect. Anything else will cause a false response.
* _expect-string_ - a string you should expect in the response from the web-server. If it's not found, a will cause a false response.
