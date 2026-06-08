const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const { URL } = require('url');

const TIMEOUT = 10000;
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';

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

function fetchUrl(url, redirectCount = 0) {
  return new Promise((resolve) => {
    if (redirectCount > 5) {
      return resolve({ status: 0, finalUrl: url, error: '重定向次数过多' });
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
      if (code >= 300 && code < 400 && res.headers.location) {
        const next = new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(fetchUrl(next, redirectCount + 1).then(r => ({
          ...r, firstStatus: r.firstStatus || code, redirectedFrom: url
        })));
      }
      res.resume();
      resolve({ status: code, finalUrl: url, error: null });
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, finalUrl: url, error: 'timeout' }); });
    req.on('error', (e) => resolve({ status: 0, finalUrl: url, error: e.message }));
    req.end();
  });
}

async function checkOne(raw) {
  const url = normalize(raw);
  let host;
  try { host = new URL(url).hostname; } catch { 
    return { domain: raw, url, status: 'URL无效', code: '—', rt: '—', ssl: '—', note: 'URL格式错误', redirect_to: '' };
  }

  const result = { domain: raw, url, status: '', code: '—', rt: '—', ssl: url.startsWith('https') ? '✓' : '✗', note: '', redirect_to: '' };

  const dnsOk = await checkDns(host);
  if (!dnsOk) {
    return { ...result, status: 'DNS失败', ssl: '—', note: '域名无法解析，可能已过期或未注册' };
  }

  const t0 = Date.now();
  const { status, finalUrl, error } = await fetchUrl(url);
  const rt = Date.now() - t0;
  result.rt = rt + ' ms';

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
