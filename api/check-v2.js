'use strict';

const legacyCheckHandler = require('./check');
const { fixBrandMismatchResult } = require('./brand-fix');

module.exports = async (req, res) => {
  const originalJson = res.json.bind(res);
  res.json = (payload) => {
    if (payload && Array.isArray(payload.results)) {
      payload = {
        ...payload,
        results: payload.results.map(fixBrandMismatchResult),
      };
    }
    return originalJson(payload);
  };

  return legacyCheckHandler(req, res);
};
