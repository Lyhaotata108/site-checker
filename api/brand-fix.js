'use strict';

const NAMED_ENTITIES = {
  '&amp;': '&',
  '&quot;': '"',
  '&apos;': "'",
  '&#39;': "'",
  '&lt;': '<',
  '&gt;': '>',
  '&nbsp;': ' ',
};

function safeCodePoint(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0x10ffff) return '';
  try { return String.fromCodePoint(value); } catch { return ''; }
}

function decodeHtmlEntities(value) {
  return String(value || '')
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => safeCodePoint(parseInt(hex, 16)))
    .replace(/&#([0-9]+);?/g, (_, decimal) => safeCodePoint(parseInt(decimal, 10)))
    .replace(/&(amp|quot|apos|lt|gt|nbsp);|&#39;/gi, match => NAMED_ENTITIES[match.toLowerCase()] || match);
}

function normalizeBrand(value) {
  return decodeHtmlEntities(value)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/\+/g, 'plus')
    .replace(/[^a-z0-9]/g, '');
}

function canonicalizeCommonPlurals(value) {
  return String(value || '')
    .replace(/massages/g, 'massage')
    .replace(/spas/g, 'spa')
    .replace(/services/g, 'service')
    .replace(/treatments/g, 'treatment')
    .replace(/therapies/g, 'therapy')
    .replace(/facials/g, 'facial')
    .replace(/nails/g, 'nail')
    .replace(/lashes/g, 'lash');
}

function getDomainCore(domain) {
  let raw = String(domain || '').trim().toLowerCase();
  try {
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
    raw = new URL(raw).hostname;
  } catch {
    raw = raw.replace(/^https?:\/\//i, '').split('/')[0];
  }
  const parts = raw.replace(/^www\./, '').split('.').filter(Boolean);
  return parts.length >= 2 ? parts[parts.length - 2] : (parts[0] || '');
}

function titleMatchesDomainBrand(domain, title) {
  const core = canonicalizeCommonPlurals(normalizeBrand(getDomainCore(domain)));
  const normalizedTitle = canonicalizeCommonPlurals(normalizeBrand(title));
  return core.length >= 5 && normalizedTitle.includes(core);
}

function fixBrandMismatchResult(result) {
  if (!result || result.status !== '内容异常' || !result.title) return result;
  if (!titleMatchesDomainBrand(result.domain || result.url, result.title)) return result;

  const decodedTitle = decodeHtmlEntities(result.title).replace(/\s+/g, ' ').trim();
  const note = decodedTitle ? `标题：${decodedTitle}` : '页面品牌与域名匹配';
  return {
    ...result,
    status: '正常',
    content: '正常',
    title: decodedTitle || result.title,
    contentNote: note,
    note,
    reviewReason: '',
  };
}

module.exports = {
  decodeHtmlEntities,
  normalizeBrand,
  canonicalizeCommonPlurals,
  getDomainCore,
  titleMatchesDomainBrand,
  fixBrandMismatchResult,
};
