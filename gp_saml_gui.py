#!/usr/bin/env python3

import argparse
import base64
import binascii
import errno
import os
import select
import secrets
import socket
import socketserver
import struct
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import urllib3
import requests
import xml.etree.ElementTree as ET
import ssl
import tempfile
import subprocess

from operator import setitem
from os import path, dup2, execvp, environ
from shlex import quote
from sys import stderr, platform
from binascii import a2b_base64
from urllib.parse import unquote, urlparse, urlencode
from html.parser import HTMLParser


def load_webkit():
    global Gtk, WebKit2, GLib
    import warnings
    try:
        import gi

        gi.require_version('Gtk', '3.0')
        try:
            gi.require_version('WebKit2', '4.1')
        except ValueError:  # I wish this were ImportError
            gi.require_version('WebKit2', '4.0')
            warnings.warn("Using WebKit2Gtk 4.0 (obsolete); please upgrade to WebKit2Gtk 4.1")
        from gi.repository import Gtk, WebKit2, GLib
    except ImportError:
        try:
            import pgi as gi
            gi.require_version('Gtk', '3.0')
            gi.require_version('WebKit2', '4.0')
            from pgi.repository import Gtk, WebKit2, GLib
            warnings.warn("Using PGI and WebKit2Gtk 4.0 (both obsolete); please upgrade to PyGObject and WebKit2Gtk 4.1")
        except ImportError:
            gi = None
    if gi is None:
        raise ImportError("Either gi (PyGObject) or pgi (obsolete) module is required.")


class CommentHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.comments = []

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


COOKIE_FIELDS = ('prelogin-cookie', 'portal-userauthcookie')


MAX_CALLBACK = 1024 * 1024
FIELDS = ('saml-auth-status', 'saml-username', 'prelogin-cookie', 'portal-userauthcookie')
DESKTOP_FILE = 'gp-saml-gui-browser.desktop'


class EntryServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_entry_server(html, port=0):
    # The entry page can contain SAML state, so expose it only over loopback.
    entry_path = '/' + secrets.token_urlsafe(32)
    content = html.encode('utf-8')

    class EntryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != entry_path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *args):
            pass

    httpd = EntryServer(('127.0.0.1', port), EntryHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread, 'http://127.0.0.1:{}{}'.format(httpd.server_port, entry_path)


def callback_address():
    if not sys.platform.startswith('linux'):
        raise ValueError('External browser callbacks currently require Linux.')
    # Abstract Unix sockets leave no stale files and allow only one pending login
    # per desktop user. Check peer credentials before reading a callback.
    return '\0gp-saml-gui-{}'.format(os.getuid())


def check_peer(connection):
    _, uid, _ = struct.unpack('3i', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    if uid != os.getuid():
        raise ValueError('Browser callback peer belongs to another user.')


class ResultParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.result = {}
        self.field = None

    def handle_starttag(self, tag, attrs):
        self.field = tag if tag in FIELDS else None
        if self.field:
            self.result[self.field] = ''

    def handle_endtag(self, tag):
        self.field = None

    def handle_data(self, data):
        if self.field:
            self.result[self.field] += data

    def handle_comment(self, data):
        parser = ResultParser()
        parser.feed(data)
        self.result.update(parser.result)


def parse_callback(url):
    if not url.startswith('globalprotectcallback:') or len(url) > MAX_CALLBACK:
        raise ValueError('Invalid GlobalProtect callback URL.')
    payload = unquote(url.split(':', 1)[1].lstrip('/'))
    if payload.startswith('cas-as'):
        raise ValueError('CAS token callbacks are not supported; use the embedded browser.')
    try:
        html = base64.b64decode(payload, validate=True).decode('utf-8')
    except (binascii.Error, UnicodeError, ValueError):
        raise ValueError('Invalid SAML callback encoding.') from None
    parser = ResultParser()
    parser.feed(html)
    result = parser.result
    if result.get('saml-auth-status') != '1':
        raise ValueError('SAML authentication failed or callback has no success status.')
    if not result.get('saml-username') or not any(result.get(k) for k in FIELDS[2:]):
        raise ValueError('SAML callback is missing a username or VPN cookie.')
    return result


def send_callback(url):
    # Validate before connecting, and never print the credential-bearing URL.
    parse_callback(url)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        try:
            client.connect(callback_address())
        except OSError:
            raise ValueError('No pending gp-saml-gui browser login was found.') from None
        check_peer(client)
        client.sendall(url.encode('utf-8'))
        client.shutdown(socket.SHUT_WR)
        if client.recv(16) != b'OK':
            raise ValueError('The pending login rejected the browser callback.')


def install_handler():
    callback_address()  # Check platform before making desktop changes.
    # Desktop Exec quoting differs from shell quoting; % is a field-code escape.
    def desktop_quote(value):
        for char in ('\\', '"', '`', '$'):
            value = value.replace(char, '\\' + char)
        return '"' + value.replace('%', '%%') + '"'

    script = str(Path(__file__).resolve())
    command = ' '.join(desktop_quote(arg) for arg in (sys.executable, script))
    data_home = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    applications = data_home / 'applications'
    applications.mkdir(parents=True, exist_ok=True)
    (applications / DESKTOP_FILE).write_text(
        '[Desktop Entry]\nType=Application\nName=gp-saml-gui browser login\n'
        'Exec={} --browser-callback %u\nNoDisplay=true\nTerminal=false\n'
        'MimeType=x-scheme-handler/globalprotectcallback;\n'.format(command), encoding='utf-8')
    subprocess.run(['xdg-mime', 'default', DESKTOP_FILE,
                    'x-scheme-handler/globalprotectcallback'], check=True)
    print('Registered gp-saml-gui for globalprotectcallback: URLs.', file=sys.stderr)


def browser_login(uri, html, timeout, verbose):
    address = callback_address()
    handler = subprocess.run(['xdg-mime', 'query', 'default',
                              'x-scheme-handler/globalprotectcallback'],
                             check=True, stdout=subprocess.PIPE, universal_newlines=True)
    #if handler.stdout.strip() != DESKTOP_FILE:
    #    raise ValueError('Run gp-saml-gui --install-browser-handler before using --external.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(address)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                raise ValueError('Another gp-saml-gui browser login is already waiting.') from None
            raise
        listener.listen(4)
        httpd = None
        thread = None
        try:
            if html:
                # Serve POST entry forms over loopback: browsers commonly block
                # navigation to data: URLs passed from other applications.
                httpd, thread, uri = start_entry_server(html)
            elif urlparse(uri).scheme not in ('http', 'https'):
                raise ValueError('SAML entry point must be an HTTP or HTTPS URL.')
            if verbose:
                print('Opening the default browser. Complete login and allow it to open '
                      'gp-saml-gui when prompted. Waiting up to {} seconds...'.format(timeout),
                      file=sys.stderr)
            deadline = time.monotonic() + timeout
            if not webbrowser.open(uri, new=2):
                raise ValueError('Could not open the default browser.')
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Browser login timed out. Check that the browser '
                                       'allows globalprotectcallback: URLs and the VPN '
                                       'supports default-browser SAML authentication.')
                listener.settimeout(remaining)
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                with client:
                    data = bytearray()
                    try:
                        check_peer(client)
                        while len(data) <= MAX_CALLBACK:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            client.settimeout(min(5, remaining))
                            chunk = client.recv(min(65536, MAX_CALLBACK + 1 - len(data)))
                            if not chunk:
                                break
                            data.extend(chunk)
                        result = parse_callback(data.decode('utf-8'))
                        client.sendall(b'OK')
                        return result
                    except (OSError, ValueError):
                        if verbose:
                            print('Ignored an invalid browser callback.', file=sys.stderr)
        finally:
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
                thread.join()


def read_private_line(timeout):
    # Read from the terminal rather than stdin, which may be used by eval or a
    # pipeline. Never echo a callback URL containing a VPN cookie.
    import termios
    try:
        tty = open('/dev/tty', 'rb', buffering=0)
    except OSError:
        raise ValueError('--remote needs an interactive terminal for the browser callback.') from None
    with tty:
        fd = tty.fileno()
        old = termios.tcgetattr(fd)
        hidden = termios.tcgetattr(fd)
        hidden[3] &= ~termios.ECHO
        data = bytearray()
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, hidden)
            print('Paste the complete globalprotectcallback: URL, then press Enter: ',
                  end='', file=sys.stderr, flush=True)
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                    raise TimeoutError('Remote browser login timed out.')
                char = os.read(fd, 1)
                if char in (b'\n', b'\r'):
                    break
                if not char:
                    raise ValueError('Terminal closed before a browser callback was received.')
                if len(data) >= MAX_CALLBACK:
                    raise ValueError('Browser callback URL is too long.')
                data.extend(char)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            print(file=sys.stderr)
    try:
        return data.decode('utf-8')
    except UnicodeError:
        raise ValueError('Browser callback URL is not valid UTF-8.') from None


def remote_login(uri, html, timeout, port):
    httpd = thread = None
    try:
        if html:
            httpd, thread, uri = start_entry_server(html, port)
            print('For a POST login, connect with SSH local forwarding: '
                  '-L {0}:127.0.0.1:{0}'.format(port), file=sys.stderr)
        elif urlparse(uri).scheme not in ('http', 'https'):
            raise ValueError('SAML entry point must be an HTTP or HTTPS URL.')
        print('Open this URL in your local browser:\n{}'.format(uri), file=sys.stderr)
        print('After login, copy the complete globalprotectcallback: URL from the '
              'browser and paste it below. Treat the URL as a password.', file=sys.stderr)
        return parse_callback(read_private_line(timeout))
    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
            thread.join()


class SAMLLoginView:
    def __init__(self, uri, html, args):

        load_webkit()
        Gtk.init(None)
        self.window = window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0

        self.closed = False
        self.success = False
        self.saml_result = {}
        self.verbose = args.verbose

        self.ctx = WebKit2.WebContext.get_default()
        if not args.verify:
            self.ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
        self.cookies = self.ctx.get_cookie_manager()
        if args.cookies:
            self.cookies.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
            self.cookies.set_persistent_storage(args.cookies, WebKit2.CookiePersistentStorage.TEXT)
        self.wview = WebKit2.WebView()

        if args.no_proxy:
            data_manager = self.ctx.get_website_data_manager()
            data_manager.set_network_proxy_settings(WebKit2.NetworkProxyMode.NO_PROXY, None)

        if args.user_agent is None:
            args.user_agent = 'PAN GlobalProtect'
        settings = self.wview.get_settings()
        settings.set_user_agent(args.user_agent)
        self.wview.set_settings(settings)

        window.resize(500, 500)
        window.add(self.wview)
        window.show_all()
        window.set_title("SAML Login")
        window.connect('delete-event', self.close)
        self.wview.connect('load-changed', self.on_load_changed)
        self.wview.connect('resource-load-started', self.log_resources)

        if html:
            self.wview.load_html(html, uri)
        else:
            self.wview.load_uri(uri)

    def close(self, window, event):
        self.closed = True
        Gtk.main_quit()

    def log_resources(self, webview, resource, request):
        if self.verbose > 1:
            print('[REQUEST] %s for resource %s' % (request.get_http_method() or 'Request', resource.get_uri()), file=stderr)
        if self.verbose > 2:
            resource.connect('finished', self.log_resource_details, request)

    def log_resource_details(self, resource, request):
        m = request.get_http_method() or 'Request'
        uri = resource.get_uri()
        rs = resource.get_response()
        h = rs.get_http_headers() if rs else None
        if h:
            ct, cl = h.get_content_type(), h.get_content_length()
            content_type = ct[0]
            charset = ct.params.get('charset') if ct.params else None
            content_details = '%d bytes of %s%s for ' % (cl, content_type, ('; charset='+charset) if charset else '')
        print('[RECEIVE] %sresource %s %s' % (content_details if h else '', m, uri), file=stderr)

    def log_resource_text(self, resource, result, content_type, charset=None, show_headers=None):
        data = resource.get_data_finish(result)
        content_details = '%d bytes of %s%s for ' % (len(data), content_type, ('; charset='+charset) if charset else '')
        print('[DATA   ] %sresource %s' % (content_details, resource.get_uri()), file=stderr)
        if show_headers:
            for h,v in show_headers.items():
                print('%s: %s' % (h, v), file=stderr)
            print(file=stderr)
        if charset or content_type.startswith('text/'):
            print(data.decode(charset or 'utf-8'), file=stderr)

    def on_load_changed(self, webview, event):
        if event != WebKit2.LoadEvent.FINISHED:
            return

        mr = webview.get_main_resource()
        uri = mr.get_uri()
        rs = mr.get_response()
        h = rs.get_http_headers() if rs else None
        ct = h.get_content_type() if h else None

        if self.verbose:
            print('[PAGE   ] Finished loading page %s' % uri, file=stderr)
        urip = urlparse(uri)
        origin = '%s %s' % ('🔒' if urip.scheme == 'https' else '🔴', urip.netloc)
        self.window.set_title("SAML Login (%s)" % origin)

        # if no response or no headers (for e.g. about:blank), skip checking this
        if not rs or not h:
            return

        # convert to normal dict
        d = {}
        h.foreach(lambda k, v: setitem(d, k.lower(), v))
        # filter to interesting headers
        fd = {name: v for name, v in d.items() if name.startswith('saml-') or name in COOKIE_FIELDS}

        if fd:
            if self.verbose:
                print("[SAML   ] Got SAML result headers: %r" % fd, file=stderr)
                if self.verbose > 1:
                    # display everything we found
                    mr.get_data(None, self.log_resource_text, ct[0], ct.params.get('charset'), d)
            self.saml_result.update(fd, server=urlparse(uri).netloc)
            self.check_done()

        if not self.success:
            if self.verbose > 1:
                print("[SAML   ] No headers in response, searching body for xml comments", file=stderr)
            # asynchronous call to fetch body content, continue processing in callback:
            mr.get_data(None, self.response_callback, ct)

    def response_callback(self, resource, result, ct):
        data = resource.get_data_finish(result)
        content = data.decode(ct.params.get("charset") or "utf-8")

        html_parser = CommentHtmlParser()
        html_parser.feed(content)

        fd = {}
        for comment in html_parser.comments:
            if self.verbose > 1:
                print("[SAML   ] Found comment in response body: '%s'" % comment, file=stderr)
            try:
                # xml parser requires valid xml with a single root tag, but our expected content
                # is just a list of data tags, so we need to improvise
                xmlroot = ET.fromstring("<fakexmlroot>%s</fakexmlroot>" % comment)
                # search for any valid first level xml tags (inside our fake root) that could contain SAML data
                for elem in xmlroot:
                    if elem.tag.startswith("saml-") or elem.tag in COOKIE_FIELDS:
                        fd[elem.tag] = elem.text
            except ET.ParseError:
                pass  # silently ignore any comments that don't contain valid xml

        if self.verbose > 1:
            print("[SAML   ] Finished parsing response body for %s" % resource.get_uri(), file=stderr)
        if fd:
            if self.verbose:
                print("[SAML   ] Got SAML result tags: %s" % fd, file=stderr)
            self.saml_result.update(fd, server=urlparse(resource.get_uri()).netloc)

        if not self.check_done():
            # Work around timing/race condition by retrying check_done after 1 second
            GLib.timeout_add(1000, self.check_done)

    def check_done(self):
        d = self.saml_result
        if 'saml-username' in d and ('prelogin-cookie' in d or 'portal-userauthcookie' in d):
            if self.verbose:
                print("[SAML   ] Got all required SAML headers, done.", file=stderr)
            self.success = True
            Gtk.main_quit()
            return True


class TLSAdapter(requests.adapters.HTTPAdapter):
    '''Adapt to older TLS stacks that would raise errors otherwise.

    We try to work around different issues:
    * Enable weak ciphers such as 3DES or RC4, that have been disabled by default
      in OpenSSL 3.0 or recent Linux distributions.
    * Enable weak Diffie-Hellman key exchange sizes.
    * Enable unsafe legacy renegotiation for servers without RFC 5746 support.

    See Also
    --------
    https://github.com/psf/requests/issues/4775#issuecomment-478198879

    Notes
    -----
    Python is missing an ssl.OP_LEGACY_SERVER_CONNECT constant.
    We have extracted the relevant value from <openssl/ssl.h>.

    '''

    def __init__(self, verify=True):
        self.verify = verify
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')
        ssl_context.options |= 1<<2  # OP_LEGACY_SERVER_CONNECT

        if not self.verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        if hasattr(ssl_context, "keylog_filename"):
            sslkeylogfile = environ.get("SSLKEYLOGFILE")
            if sslkeylogfile:
                ssl_context.keylog_filename = sslkeylogfile

        self.poolmanager = urllib3.PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                ssl_context=ssl_context)

def parse_args(args = None):
    pf2clientos = dict(linux='Linux', darwin='Mac', win32='Windows', cygwin='Windows')
    clientos2ocos = dict(Linux='linux-64', Mac='mac-intel', Windows='win')
    default_clientos = pf2clientos.get(platform, 'Windows')

    p = argparse.ArgumentParser()
    p.add_argument('server', nargs='?', help='GlobalProtect server (portal or gateway)')
    p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-C', '--cookies', default='~/.gp-saml-gui-cookies',
                   help='Use and store cookies in this file (instead of default %(default)s)')
    x.add_argument('-K', '--no-cookies', dest='cookies', action='store_const', const=None,
                   help="Don't use or store cookies at all")
    x = p.add_mutually_exclusive_group()
    p.add_argument('-i', '--ignore-redirects', action='store_true', help='Use specified gateway hostname as server, ignoring redirects')
    x.add_argument('-g','--gateway', dest='interface', action='store_const', const='gateway', default='portal',
                   help='SAML auth to gateway')
    x.add_argument('-p','--portal', dest='interface', action='store_const', const='portal',
                   help='SAML auth to portal (default)')
    g = p.add_argument_group('Client certificate')
    g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    g = p.add_argument_group('Debugging and advanced options')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-v','--verbose', default=1, action='count', help='Increase verbosity of explanatory output to stderr')
    x.add_argument('-q','--quiet', dest='verbose', action='store_const', const=0, help='Reduce verbosity to a minimum')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-x', '--external', action='store_true',
                   help='Log in using the default browser (Linux; requires browser callback handler)')
    x.add_argument('--remote', action='store_true',
                   help='Print a login URL for another machine and read the callback from the terminal')
    p.add_argument('--install-browser-handler', action='store_true',
                   help='Register this program for globalprotectcallback: URLs and exit (Linux)')
    p.add_argument('--browser-callback', metavar='URL', help=argparse.SUPPRESS)
    p.add_argument('--browser-timeout', type=int, default=300,
                   help='Seconds to wait for external or remote browser login (default: %(default)s)')
    p.add_argument('--entry-port', type=int, default=8765,
                   help='Loopback port for remote POST login over SSH forwarding (default: %(default)s)')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-P','--pkexec-openconnect', action='store_const', dest='exec', const='pkexec', help='Use PolicyKit to exec openconnect')
    x.add_argument('-S','--sudo-openconnect', action='store_const', dest='exec', const='sudo', help='Use sudo to exec openconnect')
    x.add_argument('-E','--exec-openconnect', action='store_const', dest='exec', const='exec', help='Execute openconnect directly (advanced users)')
    g.add_argument('-u','--uri', action='store_true', help='Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server')
    g.add_argument('--clientos', choices=set(pf2clientos.values()), default=default_clientos, help="clientos value to send (default is %(default)s)")
    p.add_argument('-f','--field', dest='extra', action='append', default=[],
                   help='Extra form field(s) to pass to include in the login query string (e.g. "-f magic-cookie-value=deadbeef01234567")')
    p.add_argument('--allow-insecure-crypto', dest='insecure', action='store_true',
                   help='Allow use of insecure renegotiation or ancient 3DES and RC4 ciphers')
    p.add_argument('--user-agent', '--useragent', default='PAN GlobalProtect',
                   help='Use the provided string as the HTTP User-Agent header (default is %(default)r, as used by OpenConnect)')
    p.add_argument('--no-proxy', action='store_true', help='Disable system proxy settings')
    p.add_argument('openconnect_extra', nargs='*', help="Extra arguments to include in output OpenConnect command-line")
    args = p.parse_args(args)

    if args.browser_timeout <= 0:
        p.error('--browser-timeout must be positive')
    if not 1 <= args.entry_port <= 65535:
        p.error('--entry-port must be between 1 and 65535')
    if not args.server and not (args.install_browser_handler or args.browser_callback):
        p.error('the following arguments are required: server')
    if (args.external or args.remote) and args.uri:
        p.error('--external and --remote require a GlobalProtect server hostname; --uri requires the embedded browser')

    args.ocos = clientos2ocos[args.clientos]
    args.extra = dict(x.split('=', 1) for x in args.extra)

    if args.cookies:
        args.cookies = path.expanduser(args.cookies)

    if args.cert and args.key:
        args.cert, args.key = (args.cert, args.key), None
    elif args.cert:
        args.cert = (args.cert, None)
    elif args.key:
        p.error('--key specified without --cert')
    else:
        args.cert = None

    return p, args

def main(args = None):
    p, args = parse_args(args)

    if args.install_browser_handler:
        try:
            install_handler()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            p.error(str(exc))
        return
    if args.browser_callback:
        try:
            send_callback(args.browser_callback)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            p.error(str(exc))
        return

    s = requests.Session()
    if args.insecure:
        s.mount('https://', TLSAdapter(verify=args.verify))
    s.headers['User-Agent'] = 'PAN GlobalProtect' if args.user_agent is None else args.user_agent
    s.cert = args.cert

    if2prelogin = {'portal':'global-protect/prelogin.esp','gateway':'ssl-vpn/prelogin.esp'}
    if2auth = {'portal':'global-protect/getconfig.esp','gateway':'ssl-vpn/login.esp'}

    # query prelogin.esp and parse SAML bits
    if args.uri:
        sam, uri, html = 'URI', args.server, None
    else:
        endpoint = 'https://{}/{}'.format(args.server, if2prelogin[args.interface])
        data = {'tmp':'tmp', 'kerberos-support':'yes', 'ipv6-support':'yes', 'clientVer':4100, 'clientos':args.clientos, **args.extra}
        if args.external or args.remote:
            data.setdefault('default-browser', '1')
        if args.verbose:
            print("Looking for SAML auth tags in response to %s..." % endpoint, file=stderr)
        try:
            res = s.post(endpoint, verify=args.verify, data=data)
        except Exception as ex:
            rootex = ex
            while True:
                if isinstance(rootex, ssl.SSLError):
                    break
                elif not rootex.__cause__ and not rootex.__context__:
                    break
                rootex = rootex.__cause__ or rootex.__context__
            if isinstance(rootex, ssl.CertificateError):
                p.error("SSL certificate error (try --no-verify to ignore): %s" % rootex)
            elif isinstance(rootex, ssl.SSLError):
                p.error("SSL error (try --allow-insecure-crypto to ignore): %s" % rootex)
            else:
                raise
        xml = ET.fromstring(res.content)
        if xml.tag != 'prelogin-response':
            p.error("This does not appear to be a GlobalProtect prelogin response\nCheck in browser: {}?{}".format(endpoint, urlencode(data)))
        status = xml.find('status')
        if status != None and status.text != 'Success':
            msg = xml.find('msg')
            if msg != None and msg.text == 'GlobalProtect {} does not exist'.format(args.interface):
                p.error("{} interface does not exist; specify {} instead".format(
                    args.interface.title(), '--portal' if args.interface=='gateway' else '--gateway'))
            else:
                p.error("Error in {} prelogin response: {}".format(args.interface, msg.text))
        sam = xml.find('saml-auth-method')
        sr = xml.find('saml-request')
        if sam is None or sr is None:
            p.error("{} prelogin response does not contain SAML tags (<saml-auth-method> or <saml-request> missing)\n\n"
                    "Things to try:\n"
                    "1) Spoof an officially supported OS (e.g. --clientos=Windows or --clientos=Mac)\n"
                    "2) Check in browser: {}?{}".format(args.interface.title(), endpoint, urlencode(data)))
        sam = sam.text
        sr = a2b_base64(sr.text).decode()
        if sam == 'POST':
            html, uri = sr, None
        elif sam == 'REDIRECT':
            uri, html = sr, None
        else:
            p.error("Unknown SAML method (%s)" % sam)

    if args.external or args.remote:
        if not args.uri and xml.findtext('saml-default-browser', '').lower() != 'yes':
            p.error('Server does not advertise default-browser SAML support; '
                    'use the embedded browser or ask your VPN administrator to enable it.')
        try:
            if args.remote:
                saml_result = remote_login(uri, html, args.browser_timeout, args.entry_port)
            else:
                saml_result = browser_login(uri, html, args.browser_timeout, args.verbose)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            p.error(str(exc))
        except KeyboardInterrupt:
            p.exit(1, 'Browser login cancelled.\n')
    else:
        if args.verbose:
            print("Got SAML %s, opening browser..." % sam, file=stderr)
        slv = SAMLLoginView(uri, html, args)
        Gtk.main()
        if slv.closed:
            print("Login window closed by user.", file=stderr)
            p.exit(1)
        if not slv.success:
            p.error('Login window closed without producing SAML cookies.')
        saml_result = slv.saml_result

    # extract response and convert to OpenConnect command-line
    un = saml_result.get('saml-username')
    if args.ignore_redirects:
        server = args.server
    else:
        server = saml_result.get('server', args.server)

    for cn, ifh in (('prelogin-cookie','gateway'), ('portal-userauthcookie','portal')):
        cv = saml_result.get(cn)
        if cv:
            break
    else:
        cn = ifh = None
        p.error("Didn't get an expected cookie. Something went wrong.")

    urlpath = args.interface + ":" + cn
    openconnect_args = [
        "--protocol=gp",
        "--user="+un,
        "--os="+args.ocos,
        "--usergroup="+urlpath,
        "--passwd-on-stdin",
        server
    ] + args.openconnect_extra

    if args.insecure:
        openconnect_args.insert(1, "--allow-insecure-crypto")
    if args.user_agent:
        openconnect_args.insert(1, "--useragent="+args.user_agent)
    if args.cert:
        cert, key = args.cert
        if key:
            openconnect_args.insert(1, "--sslkey="+key)
        openconnect_args.insert(1, "--certificate="+cert)
    if args.no_proxy:
        openconnect_args.insert(1, "--no-proxy")

    openconnect_command = '''    echo {} |\n        sudo openconnect {}'''.format(
        quote(cv), " ".join(map(quote, openconnect_args)))

    if args.verbose:
        # Warn about ambiguities
        if server != args.server and not args.uri:
            if args.ignore_redirects:
                print('''IMPORTANT: During the SAML auth, you were redirected from {0} to {1}. This probably '''
                      '''means you should specify {1} as the server for final connection, but we're not 100% '''
                      '''sure about this. You should probably try both; if necessary, use the '''
                      '''--ignore-redirects option to specify desired behavior.\n'''.format(args.server, server), file=stderr)
            else:
                print('''IMPORTANT: During the SAML auth, you were redirected from {0} to {1}, however the '''
                      '''redirection was ignored because you specified --ignore-redirects.\n'''.format(args.server, server), file=stderr)
        if ifh != args.interface and not args.uri:
            print('''IMPORTANT: We started with SAML auth to the {} interface, but received a cookie '''
                  '''that's often associated with the {} interface. You should probably try both.\n'''.format(args.interface, ifh),
                  file=stderr)
        print('''\nSAML response converted to OpenConnect command line invocation:\n''', file=stderr)
        print(openconnect_command, file=stderr)

        print('''\nSAML response converted to test-globalprotect-login.py invocation:\n''', file=stderr)
        print('''    test-globalprotect-login.py --user={} --clientos={} -p '' \\\n         https://{}/{} {}={}\n'''.format(
            quote(un), quote(args.clientos), quote(server), quote(if2auth[args.interface]), quote(cn), quote(cv)), file=stderr)

    if args.exec:
        print('''Launching OpenConnect with {}, equivalent to:\n{}'''.format(args.exec, openconnect_command), file=stderr)
        with tempfile.TemporaryFile('w+') as tf:
            tf.write(cv)
            tf.flush()
            tf.seek(0)
            # redirect stdin from this file, before it is closed by the context manager
            # (it will remain accessible via the open file descriptor)
            dup2(tf.fileno(), 0)
        cmd = ["openconnect"] + openconnect_args
        if args.exec == 'pkexec':
            cmd = ["pkexec", "--user", "root"] + cmd
        elif args.exec == 'sudo':
            cmd = ["sudo"] + cmd
        execvp(cmd[0], cmd)

    else:
        varvals = {
            'HOST': quote('https://%s/%s' % (server, urlpath)),
            'USER': quote(un), 'COOKIE': quote(cv), 'OS': quote(args.ocos),
        }
        print('\n'.join('%s=%s' % pair for pair in varvals.items()))

if __name__ == "__main__":
    main()
