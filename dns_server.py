
import argparse
import json
import logging
import sys

from lib.auth import auth_factory

from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server, resolve


class CaptiveDNSServerFactory(server.DNSServerFactory):
    _src_ip = None

    def __init__(self, config=None, authorities=None, caches=None, clients=None, verbose=0):
        server.DNSServerFactory.__init__(self, authorities=authorities, caches=caches, clients=clients, verbose=verbose)
        self.config = config
        self.original_resolvers = clients

    def messageReceived(self, message, proto, address=None):
        self._src_ip = unicode(address[0])
        self.resolver.resolvers = [RedirectResolver(self.config, self._src_ip),] + self.original_resolvers
        self.resolver = resolve.ResolverChain(self.resolver.resolvers)
        return server.DNSServerFactory.messageReceived(self, message, proto, address)


class RedirectResolver(object):
    def __init__(self, config, src_ip):
        self.config = config
        self.src_ip = src_ip

    def query(self, query, timeout=None):
        logging.debug("Received Query from %s: name=%s type=%s timeout=%s",
                      self.src_ip,
                      query.name.name,
                      query.type,
                      timeout)

        if query.type not in (dns.A, dns.PTR):
            logging.info("Query type %s is not supported.", query.type)
            return defer.fail(error.DomainError())

        # Native logic says never redirect
        is_auth = True

        # If config says so, let's redirect by default
        if self.config['default-action'] == 'redirect':
            is_auth = False

        if 'auth-plugin' in self.config and 'type' in self.config['auth-plugin']:
            try:
                plugin_name = self.config['auth-plugin']['type']
                plugin = auth_factory(plugin_name, self.config)
                is_auth = plugin.auth(self.src_ip, query.type, query.name.name)
                logging.debug("Answer from auth plugin '%s': %s", plugin_name, is_auth)
            except Exception:
                logging.exception("Auth plugin raised exception:")

        if is_auth:
            return defer.fail(error.DomainError())

        redirect_a_records = ['10.0.0.1',]
        redirect_ptr_records = ['portal.local.',]
        ttl = 30

        if 'ttl' in self.config:
            ttl = self.config['ttl'] or ttl

        if 'default-a-records' in self.config:
            redirect_a_records = self.config['default-a-records'] or redirect_a_records

        if 'default-ptr-records' in self.config:
            redirect_ptr_records = self.config['default-ptr-records'] or redirect_ptr_records

        answers = []
        payloads = []

        if query.type == dns.A:
            for a_rec in redirect_a_records:
                payloads.append(dns.Record_A(address=a_rec, ttl=ttl))

        # TODO: Multiple PTR records? Fix this.
        if query.type == dns.PTR:
            for ptr_rec in redirect_ptr_records:
                payloads.append(dns.Record_PTR(name=ptr_rec, ttl=ttl))

        for payload in payloads:
            logging.debug("Adding payload: %s", payload)
            answers.append(dns.RRHeader(name=query.name.name, type=query.type, payload=payload))

        logging.debug("Sending Response: answers=%s", answers)
        return defer.succeed((answers, [], []))


class CaptiveDNSServer:
    config = None
    config_defaults = {
        'tcp-port': 53,
        'udp-port': 53,
        'bind-ip': '0.0.0.0',
        'default-action': 'redirect',
        'default-a-records': ['10.0.0.1',],
        'default-ptr-records': ['portal.local.',],
        'ttl': 30,
        'resolv-conf': '/etc/resolv.conf',
        'log-level': 'info',
        'log-file': './captive-dns-server.log',
        'auth-plugin': {'type': 'AlwaysRedirect'},
    }
    resolvers = []

    def __init__(self, config_file):
        self.config = self.parse_config(config_file)
        self.config_file = config_file
        self.setup_logging()
        self.resolvers = self.get_resolvers()

    def parse_config(self, config_file):
        # TODO: Re-do config entirely. It's messy.
        with open(config_file) as cfg_fh:
            config = json.load(cfg_fh)

        for default in self.config_defaults:
            if default not in config:
                config[default] = self.config_defaults[default]

        return config

    def setup_logging(self):
        levels = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warn': logging.WARN,
            'critical': logging.CRITICAL,
            'error': logging.ERROR
        }

        loglevel = str(self.config['log-level']).lower()
        logfile = self.config['log-file']
        logformat = '%(asctime)s - %(levelname)s - %(message)s'

        logging.basicConfig(filename=logfile, level=levels[loglevel], format=logformat)

        logging.info("Starting up: %s", sys.argv[0])
        logging.info("Config File: %s", str(self.config_file))

        for key in self.config:
            logging.debug("config: %s => %s", key, self.config[key])

    def get_resolvers(self):
        resolvers = []
        _servers = None
        _resolv = None

        if 'dns-servers' in self.config and len(self.config['dns-servers']) > 0:
            logging.debug("Adding DNS resolver: %s", self.config['dns-servers'])
            _servers = self.config['dns-servers']

        if 'resolv-conf' in self.config and len(self.config['resolv-conf']) > 0:
            logging.debug("Adding DNS resolver: %s", self.config['resolv-conf'])
            _resolv = self.config['resolv-conf']

        if not _servers and not _resolv:
            raise Exception("Both dns-servers and resolv-conf config parameters are empty.")

        resolvers.append(client.Resolver(servers=_servers, resolv=_resolv))
        return resolvers

    def run(self):
        factory = CaptiveDNSServerFactory(clients=self.resolvers, config=self.config)
        protocol = dns.DNSDatagramProtocol(controller=factory)
        udp_port = self.config['udp-port'] or 53
        tcp_port = self.config['tcp-port'] or 53

        logging.info("Binding to IP %s, ports: udp=%s tcp=%s", self.config['bind-ip'], udp_port, tcp_port)

        reactor.listenUDP(udp_port, protocol, interface=self.config['bind-ip'])
        reactor.listenTCP(tcp_port, factory, interface=self.config['bind-ip'])

        reactor.run()

if __name__ == '__main__':

    args = argparse.ArgumentParser()
    args.add_argument('--config', dest='config_file', help='Configuration file (JSON)')
    args = args.parse_args()

    config_file = args.config_file or './dns-config.json'

    try:
        s = CaptiveDNSServer(config_file)
        s.run()
    except:
        logging.exception("CaptiveDNSServer raised exception:")
        raise
