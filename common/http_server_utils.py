import socket
from contextlib import closing
from http.server import BaseHTTPRequestHandler
from urllib import parse
import json


# Ugggg
# For use when a service provider doesn't account for ephemeral port numbers
# in redirect uris and so you have to explicitly register uris with ports.

_rando_reg_ports = [51283, 58641, 60089]


def try_get_free_port():
    for p in _rando_reg_ports:
        if port_in_use(p) == False:
            return p

    raise SystemError('Couldn\'t obtain a free registered port.')


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def port_in_use(port_number):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        try:
            s.bind(('', port_number))
        except OSError as e:
            if e.errno == 98:  ## address already bound
                return True
            raise e
        return False


class MyHttpServerBaseHandler(BaseHTTPRequestHandler):
    def send_success_response(self, response_content_string='',
                              extra_headers={}, code=200):
        response_len = len(response_content_string)

        self.send_response(code)
        self.send_header("Content-Length", str(response_len))

        for k, v in extra_headers.items():
            self.send_header(k, v)

        self.end_headers()
        if response_len > 0:
            self.wfile.write(response_content_string.encode())


def query_string_to_dict_without_lists(query_string):
    return dict([(key, val) if len(val) > 1 else [key, val[0]]
                 for key, val in parse.parse_qs(query_string).items()])

def join_url_components(components):
    """
    All I want is a url equivalent of join...
    :param components: string or list of strings
    :return: string
    """
    if isinstance(components, list) is False:
        return components.strip('/')

    result = components[0].strip('/')
    for component in components[1:]:
        result += '/' + component.strip('/')

    return result
