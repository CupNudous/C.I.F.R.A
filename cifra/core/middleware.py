import re
import logging
import time
import math
import json
import unicodedata
import html
from urllib.parse import unquote_plus, unquote, urlsplit
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger("security_filter")


# ---------- util helpers ----------
def multi_unquote(s):
    """Desencoda repetidamente percent-encoding e HTML-entities para tentar revelar payloads escondidos."""
    prev = None
    cur = s
    for _ in range(5):
        if cur == prev:
            break
        prev = cur
        try:
            cur = unquote_plus(cur)
            cur = unquote(cur)
        except Exception:
            pass
        try:
            cur = html.unescape(cur)
        except Exception:
            pass
        cur = unicodedata.normalize("NFKC", cur)
    return cur


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in probs)


def truncate(s: str, n=300):
    if not isinstance(s, str):
        s = str(s)
    return (s[:n] + "...") if len(s) > n else s


# ---------- signatures (compiled regex) ----------
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'\.\./'), re.compile(r'\.\.\\'),  # ../ or ..\
    re.compile(r'%2e%2e', re.IGNORECASE),  # encoded .. 
    re.compile(r'/(?:\.\.)+/?'),  # repeated
]

XSS_PATTERNS = [
    re.compile(r'<\s*script', re.IGNORECASE),
    re.compile(r'on\w+\s*=', re.IGNORECASE),  # onerror= onclick=
    re.compile(r'javascript:', re.IGNORECASE),
    re.compile(r'<\s*iframe', re.IGNORECASE),
    re.compile(r'<\s*img', re.IGNORECASE),
    re.compile(r'&lt;\s*script', re.IGNORECASE)
]

SQLI_PATTERNS = [
    re.compile(r'\bUNION\b', re.IGNORECASE),
    re.compile(r'\bSELECT\b', re.IGNORECASE),
    re.compile(r'\bINSERT\b', re.IGNORECASE),
    re.compile(r'\bUPDATE\b', re.IGNORECASE),
    re.compile(r'\bDELETE\b', re.IGNORECASE),
    re.compile(r'\bDROP\b', re.IGNORECASE),
    re.compile(r'--\s*$'),  # SQL comments
    re.compile(r'\'\s*OR\s+1=1', re.IGNORECASE),
    re.compile(r'OR\s+\'1\'=\'1', re.IGNORECASE),
    re.compile(r'\bEXEC\b', re.IGNORECASE),
    re.compile(r'\bINFORMATION_SCHEMA\b', re.IGNORECASE),
    re.compile(r'\bSLEEP\(', re.IGNORECASE)
]

SSTI_PATTERNS = [
    re.compile(r'\{\{.*?\}\}'),  # Jinja/Twig style
    re.compile(r'\{%.*?%\}'),    # Django/Jinja tags
    re.compile(r'\$\{.*?\}'),    # JS or some template syntaxes
    re.compile(r'__import__', re.IGNORECASE),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r';\s*(?:rm|wget|curl|nc|telnet)\b', re.IGNORECASE),
    re.compile(r'\|\|'), re.compile(r'&&'), re.compile(r'`'), re.compile(r'\$\(.*\)'),
]


# fields to inspect by default
DEFAULT_INSPECT_HEADERS = ['referer', 'user-agent', 'x-forwarded-for', 'host', 'origin', 'cookie']
MAX_BODY_INSPECT_SIZE = 8 * 1024  # 8KB - evita ler payloads enormes


# ---------- Middleware ----------
class SecurityFilterMiddleware:
    """
    Middleware robusto para bloquear/monitorar ataques comuns:
     - Path traversal
     - XSS
     - SQLi
     - SSTI
     - Command injection
     - High-entropy (base64/hex blobs)
     - Rate limiting por IP

    Configuração via settings.SECURITY_FILTER (dicionário). Keys suportadas:
      - ACTION: 'block' | 'redirect' | 'log'  (block envia 403)
      - REDIRECT_TO: '/login/' (quando ACTION == 'redirect')
      - EXEMPT_PATHS: list de prefixes (ex: ['/static/', '/health/'])
      - EXEMPT_IPS: list de IPs
      - EXEMPT_USER_AGENTS: list de substrings de UA
      - LOG_ONLY: True/False (força logging sem bloqueio)
      - RATE_LIMIT: {'WINDOW': 60, 'MAX': 30}
      - BLOCK_DURATION: seconds para bloquear IP após excesso
      - WHITELIST_METHODS: ['GET', 'HEAD'] etc.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        cfg = getattr(settings, 'SECURITY_FILTER', {})
        self.action = cfg.get('ACTION', 'block')
        self.redirect_to = cfg.get('REDIRECT_TO', '/login/')
        self.exempt_paths = cfg.get('EXEMPT_PATHS', ['/static/', '/health/'])
        self.exempt_ips = set(cfg.get('EXEMPT_IPS', ['127.0.0.1', '::1']))
        self.whitelist_methods = set(cfg.get('WHITELIST_METHODS', []))
        self.log_only = cfg.get('LOG_ONLY', False) or cfg.get('ACTION', None) == 'log'
        self.rate_cfg = cfg.get('RATE_LIMIT', {'WINDOW': 60, 'MAX': 60})
        self.block_duration = cfg.get('BLOCK_DURATION', 300)
        self.inspect_headers = cfg.get('INSPECT_HEADERS', DEFAULT_INSPECT_HEADERS)
        self.max_body_size = cfg.get('MAX_BODY_INSPECT_SIZE', MAX_BODY_INSPECT_SIZE)

        # precompile aggregated pattern lists
        self.path_patterns = PATH_TRAVERSAL_PATTERNS
        self.xss_patterns = XSS_PATTERNS
        self.sqli_patterns = SQLI_PATTERNS
        self.ssti_patterns = SSTI_PATTERNS
        self.cmd_patterns = CMD_INJECTION_PATTERNS

    def _is_exempt(self, request):
        host = request.get_host().split(':')[0]
        if host in self.exempt_ips:
            return True
        ip = self._get_ip(request)
        if ip in self.exempt_ips:
            return True
        path = request.path
        for p in self.exempt_paths:
            if path.startswith(p):
                return True
        if self.whitelist_methods and request.method in self.whitelist_methods:
            return True
        ua = request.META.get('HTTP_USER_AGENT', '') or ''
        for token in getattr(settings, 'SECURITY_FILTER', {}).get('EXEMPT_USER_AGENTS', []):
            if token.lower() in ua.lower():
                return True
        return False

    def _get_ip(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            # take first ip in list
            return xff.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def _rate_check(self, ip):
        # uses django cache; backend recommended: Redis for production
        key = f"sf:rate:{ip}"
        window = self.rate_cfg.get('WINDOW', 60)
        max_count = self.rate_cfg.get('MAX', 60)
        count = cache.get(key, 0)
        if count >= max_count:
            # set blocked flag
            cache.set(f"sf:block:{ip}", True, timeout=self.block_duration)
            logger.warning("Rate limit exceeded - blocking ip=%s count=%s", ip, count)
            return False
        else:
            cache.incr(key)
            # ensure key has expiration
            if cache.get(key) == 1:
                cache.expire(key, window) if hasattr(cache, 'expire') else cache.set(key, 1, timeout=window)
            return True

    def _is_blocked(self, ip):
        return cache.get(f"sf:block:{ip}", False)

    def _log_and_act(self, request, reason, details=None):
        ip = self._get_ip(request)
        info = {
            'ip': ip,
            'path': request.path,
            'method': request.method,
            'reason': reason,
            'details': truncate(details or '', 800),
            'ua': request.META.get('HTTP_USER_AGENT', '')[:300],
            'ts': int(time.time())
        }
        logger.warning("SecurityFilter triggered: %s", json.dumps(info, ensure_ascii=False))
        if self.log_only:
            return None
        if self.action == 'redirect':
            return HttpResponseRedirect(self.redirect_to)
        return HttpResponseForbidden("Ação de segurança: requisição bloqueada.")

    def _inspect_value(self, val):
        """Return reason string if suspicious, else None."""
        if not val:
            return None
        if isinstance(val, (list, tuple)):
            val = " ".join(val)
        try:
            s = str(val)
        except Exception:
            s = repr(val)

        s_norm = multi_unquote(s).strip()
        if len(s_norm) == 0:
            return None

        # Path traversal
        for pat in self.path_patterns:
            if pat.search(s_norm):
                return f"path_traversal:{pat.pattern}"

        # XSS
        for pat in self.xss_patterns:
            if pat.search(s_norm):
                return f"xss:{pat.pattern}"

        # SQLi
        for pat in self.sqli_patterns:
            if pat.search(s_norm):
                return f"sqli:{pat.pattern}"

        # SSTI
        for pat in self.ssti_patterns:
            if pat.search(s_norm):
                return f"ssti:{pat.pattern}"

        # Command injection
        for pat in self.cmd_patterns:
            if pat.search(s_norm):
                return f"cmd_injection:{pat.pattern}"

        # High-entropy blobs (base64, hex) - may indicate file upload/coded payload
        if len(s_norm) > 80:
            ent = shannon_entropy(s_norm)
            if ent > 4.2:  # empiric threshold
                return f"high_entropy(ent={ent:.2f}, len={len(s_norm)})"

        return None

    def _inspect_headers(self, request):
        for h in self.inspect_headers:
            v = request.META.get('HTTP_' + h.upper().replace('-', '_'))
            if v:
                reason = self._inspect_value(v)
                if reason:
                    return f"header:{h}:{reason}"
        # also inspect Host
        host = request.META.get('HTTP_HOST')
        if host:
            r = self._inspect_value(host)
            if r:
                return f"host:{r}"
        return None

    def _inspect_body(self, request):
        # only try to parse small bodies to avoid DoS
        try:
            length = int(request.META.get('CONTENT_LENGTH') or 0)
        except Exception:
            length = 0
        if length > self.max_body_size:
            # skip heavy bodies (could be large file upload) - optional: flag if needed
            return None

        content_type = (request.META.get('CONTENT_TYPE') or '').lower()
        body_bytes = request.body or b''
        if not body_bytes:
            return None
        try:
            text = body_bytes.decode('utf-8', errors='ignore')
        except Exception:
            text = repr(body_bytes)[:self.max_body_size]
        # if json, inspect keys and values
        if 'application/json' in content_type:
            try:
                parsed = json.loads(text)
                # flatten small json
                def walk(o):
                    if isinstance(o, dict):
                        for k, v in o.items():
                            yield k
                            yield from walk(v)
                    elif isinstance(o, list):
                        for i in o:
                            yield from walk(i)
                    else:
                        yield str(o)
                for token in walk(parsed):
                    reason = self._inspect_value(token)
                    if reason:
                        return f"json_body:{reason}"
            except Exception:
                # fallback to text inspection
                pass

        # generic text inspection
        return self._inspect_value(text)

    def _inspect_query_and_post(self, request):
        # GET
        for k, v in request.GET.lists():
            reason = self._inspect_value(k)
            if reason:
                return f"query_key:{reason}"
            reason = self._inspect_value(" ".join(v))
            if reason:
                return f"query_val:{reason}"
        # POST
        for k, v in request.POST.lists():
            reason = self._inspect_value(k)
            if reason:
                return f"post_key:{reason}"
            reason = self._inspect_value(" ".join(v))
            if reason:
                return f"post_val:{reason}"
        return None

    def __call__(self, request):
        try:
            if self._is_exempt(request):
                return self.get_response(request)

            ip = self._get_ip(request)
            if self._is_blocked(ip):
                return HttpResponseForbidden("IP temporariamente bloqueado por excesso de requisições.")

            # rate limit check (lightweight)
            if not self._rate_check(ip):
                return HttpResponseForbidden("Bloqueado por rate limiting.")

            # inspect path (and normalized path)
            # normalize path by unquoting
            try:
                normalized_path = multi_unquote(request.path)
            except Exception:
                normalized_path = request.path
            for pat in self.path_patterns:
                if pat.search(normalized_path):
                    resp = self._log_and_act(request, f"path_traversal:{pat.pattern}", details=normalized_path)
                    return resp or self.get_response(request)

            # inspect headers
            hreason = self._inspect_headers(request)
            if hreason:
                resp = self._log_and_act(request, hreason, details=str(request.headers))
                return resp or self.get_response(request)

            # inspect GET/POST keys/values
            qreason = self._inspect_query_and_post(request)
            if qreason:
                resp = self._log_and_act(request, qreason, details=f"GET/POST inspect")
                return resp or self.get_response(request)

            # inspect body
            breason = self._inspect_body(request)
            if breason:
                resp = self._log_and_act(request, breason, details=truncate(request.body.decode('utf-8', 'ignore')))
                return resp or self.get_response(request)

            # all good - pass through
            return self.get_response(request)

        except Exception as exc:
            # Fail-open: log but don't break site; safer to allow than to crash everything.
            logger.exception("SecurityFilter error (fail-open): %s", exc)
            return self.get_response(request)