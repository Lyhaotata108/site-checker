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

// 提取页面标题
function extractTitle(html) {
  const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html || '');
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) : '';
}

// 分析正文内容，识别"域名停放/出售、默认服务器页、空白页"等内容异常
// 这类页面 HTTP 状态码通常是 200，无法靠状态码发现，必须看正文
function analyzeContent(html, host) {
  const title = extractTitle(html);
  const text = (html || '');
  const lower = text.toLowerCase();
  const lowerTitle = title.toLowerCase();

  // 去标签后的可见文本长度，判断是否近乎空白
  const visible = text.replace(/<script[\s\S]*?<\/script>/gi, '')
                      .replace(/<style[\s\S]*?<\/style>/gi, '')
                      .replace(/<[^>]+>/g, '')
                      .replace(/\s+/g, ' ').trim();

  // 域名停放 / 待售 / 抢注页特征
  const parkingPatterns = [
    'domain is for sale', 'buy this domain', 'this domain is for sale',
    'domain for sale', 'is parked', 'parked free', 'domain parking',
    'purchase this domain', 'the domain', 'sedoparking', 'parkingcrew',
    'bodis.com', 'afternic', 'dan.com', 'hugedomains', 'godaddy',
    '该域名', '域名出售', '域名停放', '此域名', '域名正在出售', '域名待售',
    '本域名', '购买此域名', '米表', '域名可以转让',
  ];

  // 服务器默认页 / 占位页特征
  const defaultPatterns = [
    'welcome to nginx', 'apache2 ubuntu default page', 'apache http server test page',
    'it works!', 'iis windows server', 'welcome to caddy', 'default web site page',
    'index of /', 'directory listing for', 'this is the default',
    'site not found', 'no website configured', 'website is under construction',
    '建设中', '正在建设', '网站正在建设', '默认站点', '未绑定', '暂未开通',
    'coming soon', 'under construction',
  ];

  const hit = (arr) => arr.find(p => lower.includes(p) || lowerTitle.includes(p));

  const parkHit = hit(parkingPatterns);
  if (parkHit) {
    return { content: '可疑', contentNote: `疑似域名停放/出售页（命中"${parkHit}"）`, title };
  }
  const defHit = hit(defaultPatterns);
  if (defHit) {
    return { content: '可疑', contentNote: `疑似默认/占位页（命中"${defHit}"）`, title };
  }
  // 近乎空白页
  if (visible.length < 20) {
    return { content: '可疑', contentNote: '页面内容近乎空白', title };
  }

  // 内容与域名不符检测：页面是真实网站，但展示的是"别人的"内容
  // 思路：取域名核心词，看是否出现在【可见文本+标题】里。
  // 必须只比对可见文本，因为域名常出现在 canonical/og:url/script 等元信息里（不可见），会造成误判。
  const mismatch = checkBrandMismatch(host, visible, title);
  if (mismatch) {
    return { content: '可疑', contentNote: mismatch, title };
  }

  return { content: '正常', contentNote: title ? `标题：${title}` : '', title };
}

// 判断页面可见内容是否与域名品牌相符
// 返回 null 表示相符（或无法判断），返回字符串表示疑似不符的原因
function checkBrandMismatch(host, visibleText, title) {
  // 取主域名（去掉 www 和 TLD），例如 fourseasonsmassage.net -> fourseasonsmassage
  const parts = host.replace(/^www\./, '').split('.');
  if (parts.length < 2) return null;
  const core = parts[parts.length - 2]; // 主体部分

  // 归一化：只保留字母数字，便于比对（页面里可能有空格/连字符）
  const norm = (s) => (s || '').toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5]/g, '');
  const coreNorm = norm(core);
  if (coreNorm.length < 4) return null; // 太短的域名（如 jd、qq）跳过，避免误判

  const haystack = norm(title) + ' ' + norm(visibleText);

  // 1) 整体命中：域名核心词作为整体出现在可见文本中 -> 相符
  if (haystack.includes(coreNorm)) return null;

  // 2) 拆词命中：把域名按常见词边界切分（驼峰、连字符已被归一化），
  //    退而求其次，看是否大部分"有意义的词片段"出现在页面里。
  //    用原始 core（含连字符）切分。
  const segments = core.toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length >= 4);
  if (segments.length > 0) {
    const matched = segments.filter(seg => haystack.includes(norm(seg)));
    // 只要有任意一个有意义的片段命中，就认为相符（保守，避免误报）
    if (matched.length > 0) return null;
  }

  // 3) 域名核心词及其片段都没出现在可见文本里 -> 疑似内容与域名不符
  const shown = (title || visibleText.slice(0, 40)).slice(0, 50);
  return `内容疑似与域名不符（域名含"${core}"，页面未出现，实际标题："${shown}"）`;
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
      // 捕获正文（最多 ~80KB），用于识别停放/默认页/空白页
      let body = '';
      let size = 0;
      const MAX = 80 * 1024;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (body.length < MAX) body += chunk.toString('utf8');
        if (size > MAX) { res.destroy(); }
      });
      res.on('end', () => {
        resolve({ status: code, finalUrl: url, error: null, firstStatus: first, body, server: res.headers['server'] || '' });
      });
      res.on('close', () => {
        resolve({ status: code, finalUrl: url, error: null, firstStatus: first, body, server: res.headers['server'] || '' });
      });
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

  const result = { domain: raw, url, status: '', code: '—', firstCode: '—', rt: '—', ssl: url.startsWith('https') ? '✓' : '✗', sslNote: '', sslDays: null, content: '—', contentNote: '', title: '', note: '', redirect_to: '' };

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
  const { status, finalUrl, error, firstStatus, body } = await fetchUrl(url);
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
  if (status >= 200 && status < 300) {
    const analysis = analyzeContent(body, host);
    result.content = analysis.content;
    result.contentNote = analysis.contentNote;
    result.title = analysis.title;
    if (analysis.content === '可疑') {
      return { ...result, status: '内容异常', note: analysis.contentNote };
    }
    return { ...result, status: '正常', note: analysis.contentNote || '网站可正常访问' };
  }
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
