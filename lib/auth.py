import re
import logging


class BaseAuth(object):
    def __init__(self, config):
        self.config = config


class AlwaysRedirect(BaseAuth):
    @staticmethod
    def auth(src_ip, query_type, query_name):
        logging.debug("AlwaysRedirect enabled, redirecting to captive portal.")
        return False


class NeverRedirect(BaseAuth):
    @staticmethod
    def auth(self, src_ip, query_type, query_name):
        return True


class SimpleWebAuth(BaseAuth):
    def auth(self, src_ip, query_type, query_name):
        # We import requests here because we don't want other plugins to fail just
        # because requests is not installed. I feel we need to remove the dependency on requests.
        import requests

        url = self.config['auth-plugin']['url']
        params = {'source_ip': src_ip, 'query_type': query_type, 'query_name': query_name}
        method = 'get'
        expected_code = 200
        expected_string = 'OK'

        if 'method' in self.config:
            method = str(self.config['method']).lower()

        if 'expect-code' in self.config:
            expected_code = int(self.config['expect-code'])

        if 'expect-string' in self.config:
            expected_string = str(self.config['expect-string'])

        try:
            resp = requests.request(method, url, params=params)
        except Exception:
            logging.exception("WebAuth.auth()")
            return False

        if resp.status_code != expected_code:
            logging.error("WebAuth - Received status code %s, but expected %s", resp.status_code, expected_code)
            return False

        if expected_string in resp.text:
            return True

        logging.info("WebAuth - Expected string '%s' not found.", expected_string)
        logging.debug("WebAuth - Full output: %s", resp.text)

        return False


class ACLAuth(BaseAuth):
    def auth(self, src_ip, query_type, query_name):
        action = 'deny'
        acls = self.config['auth-plugin']['acls']

        if 'action' in self.config['auth-plugin']:
            action = self.config['auth-plugin']['action'].lower() or 'deny'

        if action not in ('deny', 'permit'):
            logging.error("ACLAuth - Found unknown action '%s', defaulting to 'deny'", action)
            action = 'deny'

        for acl in acls:
            if re.match(acl, query_name):
                logging.debug("ACLAuth - Matched ACL %s action=%s", acl, action)
                if action == 'deny':
                    return False
                return True
        return True


class PluginNotSupported(Exception):
    pass


def auth_factory(plugin, config):
    _map = {
        'SimpleWebAuth': SimpleWebAuth(config),
        'AlwaysRedirect': AlwaysRedirect(config),
        'NeverRedirect': NeverRedirect(config),
        'ACLAuth': ACLAuth(config),
    }

    if plugin not in _map:
        raise PluginNotSupported("auth_factory: Could not find class for plugin %s", plugin)

    return _map[plugin]
