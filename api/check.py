from http.server import BaseHTTPRequestHandler
import json, socket, ssl, time, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
TIMEOUT = 10

def normalize(raw):
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw

def check_dns(host):
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(host, None)
        socket.setdefaulttimeout(old)
        return True
    except Exception:
        return False

def check_one(raw):
    url = normalize(raw)
    host = urlparse(url).hostname or ""
    result = dict(domain=raw, url=url, status="", code="—", redirect_to="", rt="—", ssl="—", note="")

    if host and not check_dns(host):
        result.update(status="DNS失败", note="域名无法解析，可能已过期或未注册")
        return result

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        rt = round((time.time() - t0) * 1000)
        code = resp.status
        final = resp.url
        result["rt"] = f"{rt} ms"
        result["ssl"] = "✓" if url.startswith("https") else "✗"
        result["code"] = code
        if final != url:
            result["redirect_to"] = final

        if 200 <= code < 300:
            result.update(status="正常", note="网站可正常访问")
        elif 300 <= code < 400:
            result.update(status="重定向", note=f"→ {final}")
        else:
            result.update(status=f"HTTP {code}", note=f"状态码 {code}")

    except urllib.error.HTTPError as e:
        rt = round((time.time() - t0) * 1000)
        result["rt"] = f"{rt} ms"
        result["code"] = e.code
        result["ssl"] = "✓" if url.startswith("https") else "✗"
        if e.code == 401:   result.update(status="需要认证", note="需登录（网站存在）")
        elif e.code == 403: result.update(status="禁止访问", note="403 拒绝（网站存在）")
        elif e.code == 404: result.update(status="页面不存在", note="404 首页缺失")
        elif e.code == 502: result.update(status="网关错误", note="502 Bad Gateway，服务器异常")
        elif e.code >= 500: result.update(status="服务器错误", note=f"HTTP {e.code}")
        else:               result.update(status=f"HTTP {e.code}", note=f"状态码 {e.code}")

    except socket.timeout:
        result.update(status="超时", note=f"连接超时 (>{TIMEOUT}s)")
    except ssl.SSLError as e:
        result.update(status="SSL错误", ssl="✗", note=str(e)[:60])
    except Exception as e:
        msg = str(e).lower()
        if any(k in msg for k in ("name or service", "nodename", "resolve", "nxdomain", "getaddrinfo")):
            result.update(status="DNS失败", note="域名解析失败，可能已过期")
        elif "timed out" in msg or "timeout" in msg:
            result.update(status="超时", note=f"连接超时 (>{TIMEOUT}s)")
        elif "refused" in msg:
            result.update(status="连接拒绝", note="端口未监听")
        else:
            result.update(status="连接失败", note=str(e)[:70])

    return result


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
            domains = [d.strip() for d in data.get("domains", []) if d.strip()]
        except Exception:
            self._json(400, {"error": "invalid json"})
            return

        if not domains:
            self._json(400, {"error": "no domains"})
            return

        # Vercel functions have a time limit — check sequentially but fast
        results = [check_one(d) for d in domains[:100]]
        self._json(200, {"results": results})

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass
