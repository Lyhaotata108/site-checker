const https = require('https');
const http = require('http');
const tls = require('tls');
const dns = require('dns').promises;
const { URL } = require('url');

const TIMEOUT = 10000;
const UA_DESKTOP = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const UA_MOBILE  = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

// ─── SSL ─────────────────────────────────────────────────────────────────────
function checkSsl(host, port = 443) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: TIMEOUT }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      let daysLeft = null;
      if (cert && cert.valid_to) daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
      let ok = true, reason = '';
      if (!authorized) {
        ok = false;
        const e = String(authError || '');
        if (e.includes('EXPIRED')) reason = '证书已过期';
        else if (e.includes('SELF_SIGNED') || e.includes('SELF SIGNED')) reason = '自签名证书';
        else if (e.includes('ALT_NAME') || e.includes('HOSTNAME') || e.includes('match')) reason = '证书域名不匹配';
        else if (e.includes('UNABLE_TO_VERIFY') || e.includes('UNABLE_TO_GET')) reason = '证书链不完整';
        else reason = '证书不受信任';
      } else if (daysLeft !== null && daysLeft < 0) { ok = false; reason = '证书已过期'; }
      else if (daysLeft !== null && daysLeft <= 14) { reason = `即将过期（剩 ${daysLeft} 天）`; }
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

// ─── HTTP fetch ───────────────────────────────────────────────────────────────
function fetchUrl(url, ua, redirectCount = 0, firstStatus = null) {
  return new Promise((resolve) => {
    if (redirectCount > 5) return resolve({ status: 0, finalUrl: url, error: '重定向次数过多', firstStatus, body: '', headers: {} });
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: { 'User-Agent': ua, 'Accept': 'text/html,application/xhtml+xml,*/*', 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8' },
      timeout: TIMEOUT,
      rejectUnauthorized: false,
    }, (res) => {
      const code = res.statusCode;
      const first = firstStatus === null ? code : firstStatus;
      if (code >= 300 && code < 400 && res.headers.location) {
        const next = new URL(res.headers.location, url).toString();
        res.resume();
        return resolve(fetchUrl(next, ua, redirectCount + 1, first).then(r => ({ ...r, firstStatus: first, redirectedFrom: url })));
      }
      let body = '', size = 0;
      const MAX = 80 * 1024;
      res.on('data', (chunk) => { size += chunk.length; if (body.length < MAX) body += chunk.toString('utf8'); if (size > MAX) res.destroy(); });
      res.on('end',  () => resolve({ status: code, finalUrl: url, error: null, firstStatus: first, body, headers: res.headers }));
      res.on('close',() => resolve({ status: code, finalUrl: url, error: null, firstStatus: first, body, headers: res.headers }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, finalUrl: url, error: 'timeout', firstStatus, body: '', headers: {} }); });
    req.on('error', (e) => resolve({ status: 0, finalUrl: url, error: e.message, firstStatus, body: '', headers: {} }));
    req.end();
  });
}

// ─── DNS ─────────────────────────────────────────────────────────────────────
async function checkDns(host) {
  try { await dns.lookup(host); return true; } catch { return false; }
}

// ─── 提取标题 ─────────────────────────────────────────────────────────────────
function extractTitle(html) {
  const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html || '');
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) : '';
}

// ─── 可见文本 ─────────────────────────────────────────────────────────────────
function visibleText(html) {
  return (html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

// ─── 停放页/默认页检测 ────────────────────────────────────────────────────────
const PARKING_PATTERNS = [
  'domain is for sale','buy this domain','this domain is for sale','domain for sale',
  'is parked','parked free','domain parking','purchase this domain','sedoparking',
  'parkingcrew','bodis.com','afternic','dan.com','hugedomains',
  '该域名','域名出售','域名停放','此域名','域名正在出售','域名待售','本域名','购买此域名','米表','域名可以转让',
];
const DEFAULT_PATTERNS = [
  'welcome to nginx','apache2 ubuntu default page','apache http server test page',
  'it works!','iis windows server','welcome to caddy','default web site page',
  'index of /','directory listing for','this is the default','site not found',
  'no website configured','website is under construction',
  '建设中','正在建设','网站正在建设','默认站点','未绑定','暂未开通','coming soon','under construction',
];

// ─── 品牌词拆分 ───────────────────────────────────────────────────────────────
const GENERIC_WORDS = new Set([
  'massage','massages','spa','spas','wellness','beauty','salon','therapy','therapist',
  'relaxation','rejuvenation','treatment','treatments','facial','body','skin','care',
  'health','healthy','healing','holistic','natural','organic','herbal','aroma',
  'aromatherapy','deep','tissue','swedish','hot','stone','couples','prenatal','sports',
  'medical','acupuncture','reflexology','wax','waxing','nail','nails','lash','lashes',
  'restaurant','cafe','coffee','bar','grill','kitchen','food','dining','menu','chef',
  'studio','center','centre','clinic','shop','store','boutique','lounge','room',
  'house','home','place','space','point','zone','hub','group','team','services',
  'service','solutions','consulting','management','partners','network','media',
  'design','creative','world','life','living','style','luxury','premier','premium',
  'elite','plus','pro','best','top','grand','royal','golden','green','blue','red',
  'white','black','modern','classic','urban','local','global','city','village',
  'garden','park','lake','hill','bay','coast','beach','the','and','for','with',
]);

const DICT = [
  'massage','massages','therapy','therapist','wellness','beauty','salon','spa','spas',
  'treatment','facial','acupuncture','reflexology','healing','holistic','natural',
  'organic','aroma','aromatherapy','swedish','tissue','stone','couples','prenatal',
  'sports','medical','waxing','nail','nails','restaurant','cafe','coffee','bar',
  'grill','kitchen','food','dining','studio','center','clinic','shop','store',
  'boutique','lounge','house','group','team','services','service','solutions',
  'consulting','management','partners','network','media','design','creative',
  'world','life','living','style','luxury','premier','premium','elite','plus',
  'pro','best','top','grand','royal','golden','green','blue','red','white','black',
  'modern','classic','urban','local','global','city','village','garden','park',
  'lake','hill','bay','coast','beach','health','healthy','care','skin','body',
  'deep','hot','four','seasons','season',
].sort((a, b) => b.length - a.length);

function splitDomainWords(core) {
  const parts = core.toLowerCase().split(/[-_\d]+/).filter(p => p.length > 0);
  const allWords = [];
  for (const part of parts) {
    let s = part;
    while (s.length > 0) {
      const match = DICT.find(w => s.startsWith(w));
      if (match) { allWords.push(match); s = s.slice(match.length); }
      else {
        let cut = s.length;
        for (const w of DICT) { const idx = s.indexOf(w, 1); if (idx > 0 && idx < cut) cut = idx; }
        allWords.push(s.slice(0, cut)); s = s.slice(cut);
      }
    }
  }
  return allWords;
}

// ─── 内容分析 ─────────────────────────────────────────────────────────────────
// 返回 { content, contentNote, title, reviewReason }
// content: '正常' | '可疑' | '待审核'
function analyzeContent(html, host) {
  const title = extractTitle(html);
  const lower = (html || '').toLowerCase();
  const lowerTitle = title.toLowerCase();
  const visible = visibleText(html);

  const hit = (arr) => arr.find(p => lower.includes(p) || lowerTitle.includes(p));

  // 1. 停放/出售页 → 直接可疑
  const parkHit = hit(PARKING_PATTERNS);
  if (parkHit) return { content: '可疑', contentNote: `疑似停放/出售页（"${parkHit}"）`, title, reviewReason: '' };

  // 2. 默认/占位页 → 直接可疑
  const defHit = hit(DEFAULT_PATTERNS);
  if (defHit) return { content: '可疑', contentNote: `疑似默认/占位页（"${defHit}"）`, title, reviewReason: '' };

  // 3. 近乎空白 → 可疑
  if (visible.length < 20) return { content: '可疑', contentNote: '页面内容近乎空白', title, reviewReason: '' };

  // 4. 品牌词匹配
  const parts = host.replace(/^www\./, '').split('.');
  if (parts.length >= 2) {
    const core = parts[parts.length - 2];
    if (core && core.length >= 3) {
      const norm = (s) => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const haystack = norm(title) + ' ' + norm(visible);
      const words = splitDomainWords(core);
      const brandWords  = words.filter(w => w.length >= 4 && !GENERIC_WORDS.has(w));
      const genericWords = words.filter(w => GENERIC_WORDS.has(w));

      if (brandWords.length > 0) {
        const brandHit = brandWords.some(w => haystack.includes(norm(w)));
        if (brandHit) {
          // 品牌词命中 → 正常
        } else {
          const genericHit = genericWords.some(w => haystack.includes(norm(w)));
          const longBrands = brandWords.filter(w => w.length >= 5);
          if (longBrands.length > 0 && !genericHit) {
            // 品牌词+行业词都未命中 → 可疑
            return { content: '可疑', contentNote: `品牌词"${longBrands.join('/')}"及行业词均未出现`, title, reviewReason: '' };
          } else if (longBrands.length > 0) {
            // 有行业词但无品牌词 → 不确定，转人工
            return {
              content: '待审核',
              contentNote: `品牌词"${longBrands.join('/')}"未出现，页面有行业词但内容待确认`,
              title,
              reviewReason: `域名含品牌词"${longBrands.join('/')}"，但页面未出现该词；页面标题："${title || '（无标题）'}"`,
            };
          }
          // 品牌词太短 → 无法判断，待审核
          if (brandWords.length > 0) {
            return {
              content: '待审核',
              contentNote: `品牌词"${brandWords.join('/')}"较短（<5字符），无法自动判断`,
              title,
              reviewReason: `域名品牌词"${brandWords.join('/')}"太短，自动匹配不可靠；页面标题："${title || '（无标题）'}"`,
            };
          }
        }
      }
      // 全通用词 → 无法判断，待审核
      if (brandWords.length === 0 && genericWords.length > 0) {
        return {
          content: '待审核',
          contentNote: '域名全由通用行业词组成，无法自动判断品牌相符性',
          title,
          reviewReason: `域名"${core}"由通用词组成（${genericWords.slice(0,3).join('+')}），无品牌词可验证；页面标题："${title || '（无标题）'}"`,
        };
      }
    }
  }

  return { content: '正常', contentNote: title ? `标题：${title}` : '', title, reviewReason: '' };
}

// ─── 手机端检测 ───────────────────────────────────────────────────────────────
function analyzeMobile(html, mobileStatus, desktopStatus) {
  const issues = [];
  const warnings = [];

  // 1. 状态码异常
  if (mobileStatus === 0) {
    issues.push('手机端无法访问');
  } else if (mobileStatus !== desktopStatus && mobileStatus >= 400) {
    issues.push(`手机端返回 ${mobileStatus}，PC 端正常`);
  }

  if (!html) return { mobileScore: issues.length === 0 ? '正常' : '异常', mobileIssues: issues, mobileWarnings: warnings };

  // 2. viewport meta 标签
  const hasViewport = /<meta[^>]+name=["']viewport["'][^>]*>/i.test(html);
  if (!hasViewport) issues.push('缺少 viewport meta 标签（手机端必然缩放异常）');

  // 3. 响应式 CSS
  const hasMediaQuery = /@media\s*\(/i.test(html);
  if (!hasMediaQuery) warnings.push('未检测到响应式 CSS（@media），可能无手机端适配');

  // 4. 固定宽度检测（常见导致手机端溢出）
  const fixedWidths = [];
  const fixedRe = /(?:width|min-width)\s*:\s*(\d+)px/gi;
  let m;
  while ((m = fixedRe.exec(html)) !== null) {
    const px = parseInt(m[1]);
    if (px > 500 && px < 2000) fixedWidths.push(px);
    if (fixedWidths.length >= 5) break;
  }
  if (fixedWidths.length >= 3 && !hasMediaQuery) {
    warnings.push(`发现 ${fixedWidths.length} 处固定宽度（${fixedWidths.slice(0,3).join('/')}px），手机端可能横向溢出`);
  }

  // 5. 图片检测（src 是否有 alt，是否有 lazy load）
  const imgTags = html.match(/<img[^>]+>/gi) || [];
  const missingAlt = imgTags.filter(t => !/alt\s*=/i.test(t));
  const imgSrcs = imgTags.map(t => { const m = /src=["']([^"']+)["']/i.exec(t); return m ? m[1] : null; }).filter(Boolean);

  // 落地页关键图检测：首屏 img 是否存在
  if (imgTags.length === 0) {
    warnings.push('页面无图片，落地页可能缺少视觉内容');
  } else if (imgTags.length > 0 && missingAlt.length === imgTags.length) {
    warnings.push(`${imgTags.length} 张图片均缺少 alt 属性`);
  }

  // 6. 字体大小（手机端 <12px 会很难读）
  const tinyFont = /font-size\s*:\s*([1-9]|1[01])px/i.test(html);
  if (tinyFont) warnings.push('存在 <12px 字体，手机端可读性差');

  // 7. 点击目标（小于 44px 的按钮/链接）
  const smallTap = html.match(/(?:height|width)\s*:\s*([1-3]\d)px/gi) || [];
  if (smallTap.length >= 3) warnings.push('存在多处小尺寸元素，手机端点击区域可能过小');

  // 8. 水平滚动检测
  const overflowX = /overflow-x\s*:\s*(?:scroll|auto)/i.test(html);
  if (overflowX) warnings.push('CSS 存在 overflow-x:scroll/auto，手机端可能出现横向滚动');

  const score = issues.length > 0 ? '异常' : warnings.length > 0 ? '需关注' : '正常';
  return { mobileScore: score, mobileIssues: issues, mobileWarnings: warnings, imgCount: imgTags.length };
}

// ─── 图片资源可用性检测（抽查首屏 img src）────────────────────────────────────
async function checkImages(html, baseUrl) {
  const imgTags = html.match(/<img[^>]+>/gi) || [];
  const srcs = imgTags
    .map(t => { const m = /src=["']([^"'#?]+)["']/i.exec(t); return m ? m[1] : null; })
    .filter(Boolean)
    .filter(s => !s.startsWith('data:'))
    .slice(0, 6); // 最多检查6张

  if (srcs.length === 0) return { checked: 0, broken: [], ok: 0 };

  const results = await Promise.all(srcs.map(async (src) => {
    let fullUrl;
    try { fullUrl = new URL(src, baseUrl).toString(); } catch { return { src, ok: false, reason: 'URL无效' }; }
    return new Promise((resolve) => {
      const parsed = new URL(fullUrl);
      const mod = parsed.protocol === 'https:' ? https : http;
      const req = mod.request({
        hostname: parsed.hostname, path: parsed.pathname + parsed.search,
        method: 'HEAD', timeout: 6000, rejectUnauthorized: false,
        headers: { 'User-Agent': UA_MOBILE },
      }, (res) => {
        resolve({ src, ok: res.statusCode < 400, status: res.statusCode });
      });
      req.on('timeout', () => { req.destroy(); resolve({ src, ok: false, reason: '超时' }); });
      req.on('error', () => resolve({ src, ok: false, reason: '连接失败' }));
      req.end();
    });
  }));

  const broken = results.filter(r => !r.ok).map(r => r.src.split('/').pop().slice(0, 40));
  return { checked: srcs.length, broken, ok: results.filter(r => r.ok).length };
}

// ─── 主检测函数 ───────────────────────────────────────────────────────────────
function normalize(raw) {
  raw = raw.trim();
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  return raw;
}

async function checkOne(raw) {
  const url = normalize(raw);
  let host;
  try { host = new URL(url).hostname; } catch {
    return { domain: raw, url, status: 'URL无效', code:'—', firstCode:'—', rt:'—', ssl:'—', sslNote:'', sslDays:null, content:'—', contentNote:'', title:'', note:'', redirect_to:'', reviewReason:'', mobileScore:'—', mobileNote:'', imgBroken:0, imgChecked:0 };
  }

  const base = { domain: raw, url, status:'', code:'—', firstCode:'—', rt:'—', ssl: url.startsWith('https')?'✓':'✗', sslNote:'', sslDays:null, content:'—', contentNote:'', title:'', note:'', redirect_to:'', reviewReason:'', mobileScore:'—', mobileNote:'', imgBroken:0, imgChecked:0 };

  const dnsOk = await checkDns(host);
  if (!dnsOk) return { ...base, status:'DNS失败', ssl:'—', note:'域名无法解析，可能已过期或未注册' };

  // SSL
  if (url.startsWith('https')) {
    const port = new URL(url).port || 443;
    const sslInfo = await checkSsl(host, Number(port));
    base.sslDays = sslInfo.daysLeft;
    if (!sslInfo.ok) { base.ssl='✗'; base.sslNote=sslInfo.reason; }
    else if (sslInfo.reason) { base.ssl='⚠'; base.sslNote=sslInfo.reason; }
    else { base.ssl='✓'; base.sslNote=sslInfo.daysLeft!=null?`有效（剩 ${sslInfo.daysLeft} 天）`:'证书有效'; }
  }

  // PC + 手机端并发请求
  const t0 = Date.now();
  const [desktop, mobile] = await Promise.all([
    fetchUrl(url, UA_DESKTOP),
    fetchUrl(url, UA_MOBILE),
  ]);
  base.rt = (Date.now() - t0) + ' ms';

  if (desktop.firstStatus) base.firstCode = desktop.firstStatus;
  if (desktop.finalUrl && desktop.finalUrl !== url) base.redirect_to = desktop.finalUrl;

  // 连接失败处理
  if (desktop.error) {
    if (desktop.error==='timeout') return { ...base, status:'超时', code:'—', note:`连接超时 (>${TIMEOUT/1000}s)` };
    if (desktop.error==='重定向次数过多') return { ...base, status:'重定向过多', code:'—', note:desktop.error };
    const msg = desktop.error.toLowerCase();
    if (msg.includes('enotfound')||msg.includes('dns')) return { ...base, status:'DNS失败', note:'域名解析失败' };
    if (msg.includes('econnrefused')) return { ...base, status:'连接拒绝', note:'端口未监听' };
    if (msg.includes('ssl')||msg.includes('certificate')) return { ...base, status:'SSL错误', ssl:'✗', note:desktop.error.slice(0,60) };
    return { ...base, status:'连接失败', note:desktop.error.slice(0,70) };
  }

  base.code = desktop.status;

  if (desktop.status >= 200 && desktop.status < 300) {
    // 内容分析（基于 PC 响应）
    const analysis = analyzeContent(desktop.body, host);
    base.content      = analysis.content;
    base.contentNote  = analysis.contentNote;
    base.title        = analysis.title;
    base.reviewReason = analysis.reviewReason;

    // 手机端分析
    const mob = analyzeMobile(mobile.body || '', mobile.status || 0, desktop.status);
    base.mobileScore = mob.mobileScore;
    const mobParts = [...mob.mobileIssues, ...mob.mobileWarnings];
    base.mobileNote = mobParts.slice(0, 3).join('；') || '手机端正常';
    if (mob.imgCount !== undefined) base.imgChecked = mob.imgCount;

    // 图片可用性检测
    const imgResult = await checkImages(mobile.body || desktop.body || '', desktop.finalUrl || url);
    base.imgBroken  = imgResult.broken.length;
    base.imgChecked = imgResult.checked;
    if (imgResult.broken.length > 0) {
      base.mobileNote = (base.mobileNote ? base.mobileNote + '；' : '') + `${imgResult.broken.length}张图片无法加载（${imgResult.broken.slice(0,2).join('、')}）`;
      if (base.mobileScore === '正常') base.mobileScore = '需关注';
    }

    // 最终状态
    if (analysis.content === '可疑') return { ...base, status:'内容异常', note:analysis.contentNote };
    if (analysis.content === '待审核') return { ...base, status:'待审核', note:analysis.reviewReason || analysis.contentNote };
    if (mob.mobileScore === '异常') return { ...base, status:'手机端异常', note:mob.mobileIssues[0] || '手机端访问异常' };

    // 手机端问题降级为"需关注"
    const extraWarn = mob.mobileScore !== '正常' || base.imgBroken > 0;
    return { ...base, status: extraWarn ? '需关注' : '正常', note: analysis.contentNote || '网站可正常访问' };
  }

  if (desktop.status >= 300 && desktop.status < 400) return { ...base, status:'重定向', note:`→ ${desktop.finalUrl}` };
  if (desktop.status === 401) return { ...base, status:'需要认证', note:'需登录（网站存在）' };
  if (desktop.status === 403) return { ...base, status:'禁止访问', note:'403 拒绝（网站存在）' };
  if (desktop.status === 404) return { ...base, status:'页面不存在', note:'404 首页缺失' };
  if (desktop.status === 502) return { ...base, status:'网关错误', note:'502 Bad Gateway' };
  if (desktop.status >= 500) return { ...base, status:'服务器错误', note:`HTTP ${desktop.status}` };
  return { ...base, status:`HTTP ${desktop.status}`, note:`状态码 ${desktop.status}` };
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
  try { domains = JSON.parse(body).domains || []; } catch { return res.status(400).json({ error: 'invalid json' }); }

  domains = domains.map(d => d.trim()).filter(Boolean).slice(0, 100);
  if (!domains.length) return res.status(400).json({ error: 'no domains' });

  const results = await Promise.all(domains.map(checkOne));
  res.status(200).json({ results });
};
