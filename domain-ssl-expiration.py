#!/usr/bin/env python3

# python-whois (0.7.3)
# python 3.6.8

import whois
import ssl
import socket
import json
import datetime
from sys import argv


class SslCertifExpiration:
    __slots__ = ('site', 'ssl_port')

    def __init__(self, site: str, ssl_port: (str, int)):
        self.site = site
        self.ssl_port = ssl_port

    def check_expiration_ssl(self) -> int:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.site, self.ssl_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.site) as ssock:
                    data = json.dumps(ssock.getpeercert())
                    dictdata = json.loads(data)
                    value = datetime.datetime.strptime(dictdata['notAfter'],
                                                       '%b %d %X %Y %Z') - datetime.datetime.now()
        except socket.timeout as err:
            print("No connection: {0}".format(err))
        return value.days

    def __bool__(self):
        if isinstance(self.ssl_port, (int, str)):
            return True

    def __str__(self):
        return f'arguments are passed inside the class {self.site} and {self.ssl_port}'


class DomainExpiration:
    @staticmethod
    def check_expiration_domain(site) -> int:
        w = whois.whois(site)
        domen_value = datetime.datetime.strptime(str(w.expiration_date), '%Y-%m-%d %X') - datetime.datetime.now()
        return domen_value.days


if __name__ == "__main__":

    socket.setdefaulttimeout(3)  # timeout for socket

    web_site = argv[1]
    expiration = argv[2]  # 'domain' or 'ssl'

    if not isinstance(web_site, str):
        raise "Need a format str"

    if expiration == 'domain':
        obj = DomainExpiration.check_expiration_domain(web_site)
        print(obj)

    elif expiration == 'ssl':
        web_ssl_port = argv[3]
        obj = SslCertifExpiration(web_site, web_ssl_port)
        if obj:
            value_count = obj.check_expiration_ssl()
            print(value_count)
