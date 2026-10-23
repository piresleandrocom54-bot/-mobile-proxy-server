#!/usr/bin/env python3
"""
Mobile Proxy Server - HTTP/HTTPS proxy (RFC 7230 + metodo CONNECT) sobre TCP.

Protocolo implementado: HTTP proxy (TCP). Suporta:
  - HTTP comum (GET/POST/... com URL absoluta)
  - HTTPS via tunel CONNECT (o trafego TLS passa cifrado de ponta a ponta)
NAO implementa SOCKS5 nem UDP (iOS e Android so aceitam proxy HTTP nas
configuracoes de Wi-Fi, por isso este e o protocolo escolhido).

Autenticacao: Proxy-Authorization: Basic (usuario/senha via variaveis de ambiente).
Endpoint: GET /health  (sem autenticacao, responde "ok" em JSON).
"""
import asyncio
import base64
import hmac
import ipaddress
import json
import logging
import os
import socket
import time
import urllib.request

PORT = int(os.environ.get("PORT", "3030"))
HOST = os.environ.get("HOST", "0.0.0.0")
PROXY_USER = os.environ.get("PROXY_USER", "")
PROXY_PASS = os.environ.get("PROXY_PASS", "")
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_TARGETS", "0") == "1"
IDLE_TIMEOUT = 300
MAX_HEADER = 64 * 1024
START = time.time()

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("proxy")
PUBLIC_IP = None


def detect_public_ip():
    """Consulta o IP publico REAL da maquina (nao inventa nada)."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                ipaddress.ip_address(ip)
                return ip
        except Exception:
            continue
    return None


def check_auth(headers):
    value = headers.get("proxy-authorization", "")
    if not value.lower().startswith("basic "):
        return False
    try:
        user, _, pw = base64.b64decode(value[6:].strip()).decode().partition(":")
    except Exception:
        return False
    ok_u = hmac.compare_digest(user.encode(), PROXY_USER.encode())
    ok_p = hmac.compare_digest(pw.encode(), PROXY_PASS.encode())
    return ok_u and ok_p


def target_allowed(host):
    """Bloqueia acesso a redes internas (evita SSRF no servidor)."""
    if ALLOW_PRIVATE:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
    except socket.gaierror:
        return False
    return True


async def read_head(reader):
    data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    if len(data) > MAX_HEADER:
        raise ValueError("header too large")
    lines = data.decode("latin-1").split("\r\n")
    method, target, version = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, target, version, headers, lines


async def respond(writer, status, body=b"", extra=""):
    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}"
        f"Connection: close\r\n\r\n".encode() + body
    )
    await writer.drain()


async def pipe(src, dst):
    try:
        while True:
            chunk = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except Exception:
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    client = f"{peer[0]}:{peer[1]}" if peer else "?"
    try:
        method, target, version, headers, lines = await read_head(reader)
    except Exception as e:
        log.warning("client=%s bad request: %s", client, type(e).__name__)
        writer.close()
        return

    # /health (acesso direto, sem proxy)
    if method == "GET" and target in ("/health", "/health/"):
        body = json.dumps({
            "status": "ok",
            "protocol": "HTTP proxy (TCP) com CONNECT para HTTPS",
            "port": PORT,
            "public_ip": PUBLIC_IP or "indisponivel",
            "uptime_s": int(time.time() - START),
        }).encode()
        await respond(writer, "200 OK", body, "Content-Type: application/json\r\n")
        writer.close()
        log.info("client=%s health ok", client)
        return

    if not check_auth(headers):
        log.warning("client=%s auth failed method=%s", client, method)
        await respond(writer, "407 Proxy Authentication Required", b"auth required",
                      'Proxy-Authenticate: Basic realm="MobileProxy"\r\n')
        writer.close()
        return

    try:
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            host, port = host.strip("[]"), int(port or 443)
            if not target_allowed(host):
                raise PermissionError
            r2, w2 = await asyncio.wait_for(asyncio.open_connection(host, port), 15)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            log.info("client=%s CONNECT %s:%s", client, host, port)
        else:
            if not target.startswith("http://"):
                await respond(writer, "400 Bad Request", b"absolute http:// URL required")
                writer.close()
                return
            rest = target[7:]
            hostport, _, path = rest.partition("/")
            host, _, port = hostport.partition(":")
            port = int(port or 80)
            if not target_allowed(host):
                raise PermissionError
            r2, w2 = await asyncio.wait_for(asyncio.open_connection(host, port), 15)
            out = [f"{method} /{path} {version}"]
            for line in lines[1:]:
                k = line.split(":", 1)[0].strip().lower()
                if line and k not in ("proxy-authorization", "proxy-connection"):
                    out.append(line)
            w2.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
            await w2.drain()
            log.info("client=%s %s http://%s:%s", client, method, host, port)
        await asyncio.gather(pipe(reader, w2), pipe(r2, writer))
    except PermissionError:
        log.warning("client=%s blocked private target", client)
        await respond(writer, "403 Forbidden", b"target not allowed")
        writer.close()
    except Exception as e:
        log.error("client=%s upstream error: %s", client, type(e).__name__)
        try:
            await respond(writer, "502 Bad Gateway", b"upstream error")
        except Exception:
            pass
        writer.close()


async def main():
    global PUBLIC_IP
    if not PROXY_USER or len(PROXY_PASS) < 12:
        raise SystemExit("Defina PROXY_USER e PROXY_PASS (minimo 12 caracteres).")
    PUBLIC_IP = await asyncio.to_thread(detect_public_ip)
    server = await asyncio.start_server(handle, HOST, PORT)
    log.info("Mobile Proxy Server (HTTP proxy/TCP) ouvindo em %s:%s", HOST, PORT)
    log.info("IP publico detectado: %s", PUBLIC_IP or "indisponivel")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
