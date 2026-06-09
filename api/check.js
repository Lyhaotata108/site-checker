const https = require('https');
const http = require('http');
const tls = require('tls');
const dns = require('dns').promises;
const { URL } = require('url');

const TIMEOUT = 10000;
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';

// 单独做一次 TLS 握手，校验证书真实有效性（不忽略证书错误）
function checkSsl(host, port = 443) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };

    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false, // 不主动断开，自己判断 authorized
      timeout: TIMEOUT,
    }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;

      let daysLeft = null;
      if (cert && cert.valid_to) {
        daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
      }

      let ok = true;
      let reason = '';
      if (!authorized) {
        ok = false;
        const e = String(authError || '');
        if (e.includes('EXPIRED')) reason = '证书已过期';
        else if (e.includes('SELF_SIGNED') || e.includes('SELF SIGNED')) reason = '自签名证书';
        else if (e.includes('ALT_NAME') || e.includes('HOSTNAME') || e.includes('match')) reason = '证书域名不匹配';
        else if (e.includes('UNABLE_TO_VERIFY') || e.includes('UNABLE_TO_GET')) reason = '证书链不完整';
        else reason = '证书不受信任';
      } else if (daysLeft !== null && daysLeft < 0) {
        ok = false;
        reason = '证书已过期';
      } else if (daysLeft !== null && daysLeft <= 14) {
        reason = `即将过期（剩 ${daysLeft} 天）`;
      }

      socket.end();
      finish({ ok, reason, daysLeft, issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || '') : '' });
    });

    socket.on('timeout', () => { socket.destroy(); finish({ ok: false, reason: 'TLS 握手超时', daysLeft: null, issuer: '' }); });
    socket.on('error', (e) => {
      const msg = String(e.message || e).toLowerCase();
      let reason = '无法建立安全连接';
      if (msg.includes('expired')) reason = '证书已过期';
      else if (msg.includes('self') && msg.includes('signed')) reason = '自签名证书';
      else if (msg.includes('altname') || msg.includes('hostname')) reason = '证书域名不匹配';
      finish({ ok: false, reason, daysLeft: null, issuer: '' });
    });
  });
}

function normalize(raw) {
  raw = raw.trim();
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  return raw;
}

async function checkDns(host) {
  try {
    await dns.lookup(host);
    return true;
  } catch {
    return false;
  }
}

function fetchUrl(url, redirectCount = 0, firstStatus = null) {
  return new Promise((resolve) => {
    if (redirectCount > 5) {
      return resolve({ status: 0, finalUrl: url, error: '重定向次数过多', firstStatus });
    }
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: { 'User-Agent': UA },
      timeout: TIMEOUT,
      rejectUnauthorized: false,
    };
    const req = mod.request(options, (res) => {
      const code = res.statusCode;
      // 记录整条链路中第一次访问的状态码
      const first = firstStatus === null ? code : firstStatus;
      if (code >= 300 && code < 400 && res.headers.location) {
        const next = new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(fetchUrl(next, redirectCount + 1, first).then(r => ({
          ...r, firstStatus: first, redirectedFrom: url
        })));
      }
      res.resume();
      resolve({ status: code, finalUrl: url, error: null, firstStatus: first });
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, finalUrl: url, error: 'timeout', firstStatus }); });
    req.on('error', (e) => resolve({ status: 0, finalUrl: url, error: e.message, firstStatus }));
    req.end();
  });
}

async function checkOne(raw) {
  const url = normalize(raw);
  let host;
  try { host = new URL(url).hostname; } catch { 
    return { domain: raw, url, status: 'URL无效', code: '—', rt: '—', ssl: '—', note: 'URL格式错误', redirect_to: '' };
  }

  const result = { domain: raw, url, status: '', code: '—', firstCode: '—', rt: '—', ssl: url.startsWith('https') ? '✓' : '✗', sslNote: '', sslDays: null, note: '', redirect_to: '' };

  const dnsOk = await checkDns(host);
  if (!dnsOk) {
    return { ...result, status: 'DNS失败', ssl: '—', note: '域名无法解析，可能已过期或未注册' };
  }

  // https 站点单独校验证书有效性
  if (url.startsWith('https')) {
    const port = new URL(url).port || 443;
    const sslInfo = await checkSsl(host, Number(port));
    result.sslDays = sslInfo.daysLeft;
    if (!sslInfo.ok) {
      result.ssl = '✗';
      result.sslNote = sslInfo.reason;
    } else if (sslInfo.reason) {
      result.ssl = '⚠';
      result.sslNote = sslInfo.reason;
    } else {
      result.ssl = '✓';
      result.sslNote = sslInfo.daysLeft !== null ? `有效（剩 ${sslInfo.daysLeft} 天）` : '证书有效';
    }
  }

  const t0 = Date.now();
  const { status, finalUrl, error, firstStatus } = await fetchUrl(url);
  const rt = Date.now() - t0;
  result.rt = rt + ' ms';
  if (firstStatus) result.firstCode = firstStatus;

  if (finalUrl && finalUrl !== url) result.redirect_to = finalUrl;

  if (error) {
    if (error === 'timeout') return { ...result, status: '超时', code: '—', note: `连接超时 (>${TIMEOUT/1000}s)` };
    if (error === '重定向次数过多') return { ...result, status: '重定向过多', code: '—', note: error };
    const msg = error.toLowerCase();
    if (msg.includes('enotfound') || msg.includes('dns')) return { ...result, status: 'DNS失败', note: '域名解析失败' };
    if (msg.includes('econnrefused')) return { ...result, status: '连接拒绝', note: '端口未监听' };
    if (msg.includes('ssl') || msg.includes('certificate')) return { ...result, status: 'SSL错误', ssl: '✗', note: error.slice(0, 60) };
    return { ...result, status: '连接失败', note: error.slice(0, 70) };
  }

  result.code = status;
  if (status >= 200 && status < 300) return { ...result, status: '正常', note: '网站可正常访问' };
  if (status >= 300 && status < 400) return { ...result, status: '重定向', note: `→ ${finalUrl}` };
  if (status === 401) return { ...result, status: '需要认证', note: '需登录（网站存在）' };
  if (status === 403) return { ...result, status: '禁止访问', note: '403 拒绝（网站存在）' };
  if (status === 404) return { ...result, status: '页面不存在', note: '404 首页缺失' };
  if (status === 502) return { ...result, status: '网关错误', note: '502 Bad Gateway' };
  if (status >= 500) return { ...result, status: '服务器错误', note: `HTTP ${status}` };
  return { ...result, status: `HTTP ${status}`, note: `状态码 ${status}` };
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' });

  let body = '';
  for await (const chunk of req) body += chunk;

  let domains;
  try {
    domains = JSON.parse(body).domains || [];
  } catch {
    return res.status(400).json({ error: 'invalid json' });
  }

  domains = domains.map(d => d.trim()).filter(Boolean).slice(0, 100);
  if (!domains.length) return res.status(400).json({ error: 'no domains' });

  const results = await Promise.all(domains.map(checkOne));
  res.status(200).json({ results });
};
