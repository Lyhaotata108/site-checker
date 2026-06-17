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

// ─── 提取品牌搜索用的全量文本 ──────────────────────────────────────────────────
// 比 visibleText 更全：额外提取 alt/title属性、meta description/keywords/og:title
// 这样品牌词出现在 logo alt、h1、导航、footer、meta 任何地方都能命中
function extractBrandHaystack(html) {
  const h = html || '';

  // 1. alt="..." 和 title="..." 属性值（logo、图片描述里常有品牌名）
  const attrTexts = [];
  const attrRe = /\b(?:alt|title)\s*=\s*["']([^"']{2,100})["']/gi;
  let am;
  while ((am = attrRe.exec(h)) !== null) attrTexts.push(am[1]);

  // 2. meta name="description/keywords" 和 og:title / og:site_name
  const metaRe = /<meta[^>]+(?:name|property)\s*=\s*["'](?:description|keywords|og:title|og:site_name|twitter:title)[^>]*content\s*=\s*["']([^"']{2,200})["'][^>]*>/gi;
  const metaRe2 = /<meta[^>]+content\s*=\s*["']([^"']{2,200})["'][^>]*(?:name|property)\s*=\s*["'](?:description|keywords|og:title|og:site_name|twitter:title)["'][^>]*>/gi;
  let mm;
  while ((mm = metaRe.exec(h)) !== null)  attrTexts.push(mm[1]);
  while ((mm = metaRe2.exec(h)) !== null) attrTexts.push(mm[1]);

  // 3. 可见正文（去掉 script/style 后剥离标签）
  const visible = h
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ').trim();

  return (attrTexts.join(' ') + ' ' + visible).slice(0, 200000);
}

// ─── 可见文本（用于停放页检测，保持原逻辑）────────────────────────────────────
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
  // 品牌匹配用全量文本（含 alt/meta/og），比纯可见文本覆盖更全
  const brandHaystack = extractBrandHaystack(html);

  const hit = (arr) => arr.find(p => lower.includes(p) || lowerTitle.includes(p));

  // 1. 停放/出售页 → 直接可疑
  const parkHit = hit(PARKING_PATTERNS);
  if (parkHit) return { content: '可疑', contentNote: `疑似停放/出售页（"${parkHit}"）`, title, reviewReason: '' };

  // 2. 默认/占位页 → 直接可疑
  const defHit = hit(DEFAULT_PATTERNS);
  if (defHit) return { content: '可疑', contentNote: `疑似默认/占位页（"${defHit}"）`, title, reviewReason: '' };

  // 3. 内容太少 → 区分两种情况
  // a) 完全空白（<20字符）且无标题 → 真的空页面，可疑
  // b) 有标题但正文很短 → 可能是 WAF/CDN 拦截了爬虫返回了空壳，不能直接判异常
  if (visible.length < 20) {
    if (!title || title.length < 3) {
      return { content: '可疑', contentNote: '页面内容近乎空白', title, reviewReason: '' };
    }
    // 有标题说明页面真实存在，只是内容被反爬拦截，进待审核
    return {
      content: '待审核',
      contentNote: '页面正文被反爬拦截，仅获取到标题',
      title,
      reviewReason: `服务器可能对自动检测做了拦截，仅能读取到标题："${title}"，建议人工打开确认`,
    };
  }

  // 4. 品牌匹配
  // 归一化：只保留字母和数字（去掉连字符、空格、大小写）
  // 这样 "a1-massage" == "a1 massage" == "A1 Massage" == "A1Massage"
  // 归一化：西里尔/希腊字母 → ASCII 近似字符，再去掉非字母数字
  // 处理品牌名使用了视觉相似字符的情况（如 е=1077 是西里尔字母，看起来像 e）
  const CONFUSABLES = {'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y',
    'і':'i','ѕ':'s','ɑ':'a','ɡ':'g','ℬ':'b','ℰ':'e','ℱ':'f','ℋ':'h','ℐ':'i',
    'ℒ':'l','ℳ':'m','ℛ':'r','ℬ':'b','à':'a','á':'a','â':'a','ã':'a','ä':'a',
    'å':'a','è':'e','é':'e','ê':'e','ë':'e','ì':'i','í':'i','î':'i','ï':'i',
    'ò':'o','ó':'o','ô':'o','õ':'o','ö':'o','ù':'u','ú':'u','û':'u','ü':'u',
    'ý':'y','ñ':'n','ç':'c',
  };
  const norm = (s) => {
    if (!s) return '';
    // 先把已知混淆字符替换为 ASCII
    let r = s.toLowerCase();
    for (const [k, v] of Object.entries(CONFUSABLES)) r = r.split(k).join(v);
    return r.replace(/\+/g, 'plus').replace(/[^a-z0-9]/g, '');
  };

  // 常见地理缩写后缀（美国州缩写 + 部分城市缩写），注册域名时常附在品牌名后
  // footyrootysc → sc=South Carolina，剥离后得到真正的品牌词 footyrooty
  const GEO_SUFFIXES = new Set([
    'sc','nc','ny','nj','la','ca','tx','fl','ga','va','pa','oh','mi','il','wa',
    'az','co','ut','nv','or','mn','mo','wi','in','tn','md','ma','ct','ky','al',
    'ok','ar','ia','ms','ks','ne','id','mt','nd','sd','wv','nm','me','nh','vt',
    'wy','ak','hi','dc','pr',
    // 城市常见缩写
    'nyc','atl','chi','hou','phx','sea','pdx','lax','sfb','dfw','mia','bos',
    'mtl','van','tor',
  ]);

  const parts = host.replace(/^www\./, '').split('.');
  if (parts.length >= 2) {
    const core = parts[parts.length - 2]; // 如 "a1-massage"、"footyrootysc"
    if (core && core.length >= 2) {
      const coreNorm = norm(core);

      // 尝试剥离地理后缀，生成候选核心词列表
      // footyrootysc → [footyrootysc, footyrooty]（sc是后缀）
      const coreCandidates = [coreNorm];
      const coreParts = core.toLowerCase().split('-');
      const lastPart = coreParts[coreParts.length - 1];
      if (GEO_SUFFIXES.has(lastPart) && coreParts.length > 1) {
        // 连字符分割的最后一段是地理缩写：jinye-spas-sc → jinye-spas
        coreCandidates.push(norm(coreParts.slice(0, -1).join('-')));
      } else {
        // 无连字符时从末尾截：footyrootysc → 尝试去掉2-3字符后缀
        for (const sfx of GEO_SUFFIXES) {
          if (coreNorm.endsWith(sfx) && coreNorm.length > sfx.length + 3) {
            coreCandidates.push(coreNorm.slice(0, -sfx.length));
            break;
          }
        }
      }

      // ── 第一优先：标题匹配（最可靠的信号）──────────────────────────────────
      const normTitle = norm(title);
      if (normTitle && coreCandidates.some(c => normTitle.includes(c))) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }

      // ── 第二：拆词比例匹配 ────────────────────────────────────────────────────
      // 把域名按连字符 + 词典拆成词列表，统计有多少词出现在标题里
      // 这样能处理：
      //   词序不同：bodytherapyandreflexology → title 里有 body/therapy/reflexology
      //   标题比域名短：aromamassage-spa → title "Aroma Massage" 含 aroma+massage
      //   全通用词域名：bay-spamassage → title "Bay Spa" 含 bay+spa
      const domainWords = splitDomainWords(core);
      const allWordNorms = domainWords.map(norm).filter(w => w.length >= 2);
      const nonGeneric   = domainWords.filter(w => !GENERIC_WORDS.has(w));
      const normNonGeneric = nonGeneric.map(norm).filter(w => w.length >= 2);

      function wordMatchRatio(haystack) {
        if (allWordNorms.length === 0) return 0;
        const matched = allWordNorms.filter(w => haystack.includes(w));
        return matched.length / allWordNorms.length;
      }

      // 标题里匹配比例 ≥ 50% → 正常（超过一半的域名词出现在标题里，基本可以确认）
      const titleRatio = wordMatchRatio(normTitle);
      if (titleRatio >= 0.5) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }

      // 非通用词：有任意一个命中标题 → 正常（品牌专有词命中权重更高）
      if (normNonGeneric.length > 0 && normNonGeneric.some(w => normTitle.includes(w))) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }

      // ── 第三：全量文本兜底匹配（alt/meta/og/正文全覆盖）─────────────────────
      // 品牌词可能只出现在 logo alt、meta description、og:title、h1、footer 里
      // 用 extractBrandHaystack 比纯可见文本覆盖更全，避免漏判
      const normBrand = norm(brandHaystack);
      const haystackFull = normTitle + normBrand;

      if (haystackFull.includes(coreNorm)) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }
      // 候选词（含地理缩写剥离后的版本）任意命中
      if (coreCandidates.some(c => c !== coreNorm && haystackFull.includes(c))) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }
      if (wordMatchRatio(haystackFull) >= 0.5) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }
      if (normNonGeneric.length > 0 && normNonGeneric.some(w => w.length >= 3 && haystackFull.includes(w))) {
        return { content: '正常', contentNote: `标题：${title}`, title, reviewReason: '' };
      }

      // ── 第四：无有效标题，但正文有内容 ─────────────────────────────────────────
      // 有些网站用 JS 动态渲染标题，服务端返回的 HTML 里 <title> 是空的
      // 正文匹配前面已经做过，到这里说明正文里也没命中 → 待审核而非直接可疑
      if (!title || title.length < 3) {
        return {
          content: '待审核',
          contentNote: '页面无标题（可能由 JS 动态渲染），建议人工打开确认',
          title,
          reviewReason: `域名"${core}"的页面未检测到 <title> 标签，可能使用了 JS 渲染，自动检测无法判断内容`,
        };
      }

      // ── 第五：标题和正文都匹配不上 → 按域名类型区分处理 ─────────────────────
      const allGeneric = nonGeneric.length === 0;
      if (allGeneric) {
        // 全通用词域名，自动判断本就不可靠，进人工审核
        return {
          content: '待审核',
          contentNote: `域名词未充分出现在页面中`,
          title,
          reviewReason: `域名"${core}"由通用词组成，词典匹配比例 ${Math.round(titleRatio*100)}%；页面标题："${title}"`,
        };
      } else {
        // 有专有词但完全没命中 → 可疑（真正的停放/劫持页）
        return {
          content: '可疑',
          contentNote: `域名关键词未出现在标题或页面中（标题："${title.slice(0, 60)}"）`,
          title,
          reviewReason: '',
        };
      }
    }
  }

  return { content: '正常', contentNote: title ? `标题：${title}` : '', title, reviewReason: '' };
}

// ─── 手机端检测 ───────────────────────────────────────────────────────────────
// 只检测「肉眼可见的硬性问题」，不检测可能被正常覆盖的 CSS 特征
function analyzeMobile(html, mobileStatus, desktopStatus) {
  const issues = [];   // 严重：手机端真的不可用
  const warnings = []; // 提示：可能有问题，但不升级为"需关注"

  // 1. 手机端访问失败（状态码层面的硬性问题）
  if (mobileStatus === 0) {
    issues.push('手机端无法访问（连接失败）');
  } else if (mobileStatus >= 400 && mobileStatus !== desktopStatus) {
    issues.push(`手机端返回 ${mobileStatus}，PC 端返回 ${desktopStatus}`);
  }

  if (!html) {
    const score = issues.length > 0 ? '异常' : '正常';
    return { mobileScore: score, mobileIssues: issues, mobileWarnings: warnings, imgCount: 0 };
  }

  // 2. 缺少 viewport → 这是真正会导致手机端缩放错乱的硬性问题
  const hasViewport = /<meta[^>]+name=["']viewport["'][^>]*>/i.test(html);
  if (!hasViewport) {
    issues.push('缺少 viewport meta 标签，手机端页面会缩小显示');
  }

  // 3. 页面完全没有任何图片（img + background-image 都没有）→ 落地页视觉内容缺失
  const imgTags = html.match(/<img[^>]+>/gi) || [];
  const hasBgImage = /background-image\s*:\s*url\s*\(/i.test(html);
  if (imgTags.length === 0 && !hasBgImage) {
    warnings.push('页面无图片内容（含背景图），落地页视觉可能缺失');
  }

  // 只有 issues（硬性问题）才影响得分，warnings 仅记录不升级
  const score = issues.length > 0 ? '异常' : '正常';
  return { mobileScore: score, mobileIssues: issues, mobileWarnings: warnings, imgCount: imgTags.length };
}

// ─── 图片资源可用性检测 ───────────────────────────────────────────────────────
// 同时扫描 <img src> 和 background-image: url(...)
async function checkImages(html, baseUrl) {
  const imgUrls = new Set();

  // 来源1：<img src="...">
  const imgTags = html.match(/<img[^>]+>/gi) || [];
  for (const tag of imgTags) {
    // 支持 src 和 data-src（懒加载）
    const m = /(?:data-src|src)=["']([^"'#?]+)["']/i.exec(tag);
    if (m) imgUrls.add(m[1]);
  }

  // 来源2：扫描所有 CSS url()，覆盖以下所有写法：
  //   background-image: url("...")
  //   background: linear-gradient(...), url('...')
  //   background: url(...) no-repeat center
  // 直接全局匹配 url(...)，不限制前缀属性名
  const bgRe = /url\(\s*["']?([^"')#?\s]+)["']?\s*\)/gi;
  let bm;
  while ((bm = bgRe.exec(html)) !== null) {
    const u = bm[1].trim();
    // 只保留看起来像图片的 URL（有扩展名或明确是图片路径）
    if (/\.(jpe?g|png|webp|avif|bmp|tiff?)([?#]|$)/i.test(u) || u.startsWith('http')) {
      imgUrls.add(u);
    }
  }

  // 过滤：去掉 data URI、SVG 占位、明显的 icon 小图
  const srcs = [...imgUrls]
    .filter(s => !s.startsWith('data:'))
    .filter(s => !/\.(ico|svg|gif)(\?|$)/i.test(s))
    .slice(0, 8); // 最多检查8个

  if (srcs.length === 0) return { checked: 0, broken: [], ok: 0 };

  const results = await Promise.all(srcs.map(async (src) => {
    let fullUrl;
    try { fullUrl = new URL(src, baseUrl).toString(); } catch { return { src, ok: false }; }
    return new Promise((resolve) => {
      const parsed = new URL(fullUrl);
      const mod = parsed.protocol === 'https:' ? https : http;
      const req = mod.request({
        hostname: parsed.hostname, path: parsed.pathname + parsed.search,
        method: 'HEAD', timeout: 6000, rejectUnauthorized: false,
        headers: { 'User-Agent': UA_MOBILE },
      }, (res) => resolve({ src, ok: res.statusCode < 400, status: res.statusCode }));
      req.on('timeout', () => { req.destroy(); resolve({ src, ok: false }); });
      req.on('error', () => resolve({ src, ok: false }));
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

    // 手机端分析（只有硬性问题才影响状态：连接失败 / 缺少viewport）
    const mob = analyzeMobile(mobile.body || '', mobile.status || 0, desktop.status);
    base.mobileScore = mob.mobileScore;
    base.mobileNote  = mob.mobileIssues.join('；') || '正常';

    // 图片可用性检测（img + background-image）
    const imgResult = await checkImages(mobile.body || desktop.body || '', desktop.finalUrl || url);
    base.imgBroken  = imgResult.broken.length;
    base.imgChecked = imgResult.checked;
    // 图片缺失只记录到 mobileNote，不改变手机端评分和整体状态
    // 原因：HEAD 请求常被 CDN/防盗链拦截产生误报，视觉是否缺失需人工确认
    if (imgResult.broken.length > 0) {
      base.mobileNote += (base.mobileNote !== '正常' ? '；' : '') +
        `${imgResult.broken.length}/${imgResult.checked} 张图片请求失败（可能被防盗链拦截，建议人工确认）`;
    }

    // 最终状态
    if (analysis.content === '可疑')   return { ...base, status:'内容异常',  note:analysis.contentNote };
    if (analysis.content === '待审核') return { ...base, status:'待审核',    note:analysis.reviewReason || analysis.contentNote };
    if (mob.mobileScore === '异常')    return { ...base, status:'手机端异常', note:mob.mobileIssues[0] || '手机端访问异常' };
    return { ...base, status:'正常', note: analysis.contentNote || '网站可正常访问' };
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
