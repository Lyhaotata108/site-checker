'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  decodeHtmlEntities,
  titleMatchesDomainBrand,
  fixBrandMismatchResult,
} = require('../api/brand-fix');

test('decodes named and numeric HTML entities', () => {
  assert.equal(
    decodeHtmlEntities('M &amp; J Massage &#8211; Victorville'),
    'M & J Massage – Victorville'
  );
});

test('matches initials and common singular/plural brand variants', () => {
  assert.equal(
    titleMatchesDomainBrand('mjmassages.com', 'M &amp; J Massage &#8211; 15191 7th St'),
    true
  );
});

test('converts the mjmassages false positive to normal', () => {
  const result = fixBrandMismatchResult({
    domain: 'mjmassages.com',
    status: '内容异常',
    content: '可疑',
    title: 'M &amp; J Massage &#8211; 15191 7th St #3, Victorville, CA',
    note: '域名关键词未出现在标题或页面中',
  });
  assert.equal(result.status, '正常');
  assert.equal(result.content, '正常');
  assert.match(result.title, /^M & J Massage –/);
});

test('does not override a genuine title mismatch', () => {
  const result = {
    domain: 'mjmassages.com',
    status: '内容异常',
    title: 'Completely Different Business',
  };
  assert.deepEqual(fixBrandMismatchResult(result), result);
});
