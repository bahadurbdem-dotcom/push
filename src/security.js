'use strict';
const crypto = require('crypto');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const sha256hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

/* অ্যাডমিন চাবি যাচাই (টাইমিং-সেফ) */
function adminAuth(req, res, next) {
  const key = process.env.ADMIN_KEY || '';
  if (key.length < 16) {
    return res.status(500).json({ ok: false, code: 'no_admin_key', error: 'সার্ভারে ADMIN_KEY সেট করা নেই (কমপক্ষে ১৬ অক্ষর)' });
  }
  const given = String(req.get('x-admin-key') || '');
  if (!given || !crypto.timingSafeEqual(sha(given), sha(key))) {
    return res.status(401).json({ ok: false, code: 'bad_key', error: 'অ্যাডমিন চাবি ভুল' });
  }
  next();
}

/* সহজ রেট-লিমিটার (মেমোরিতে; সার্ভার রিস্টার্ট হলে রিসেট হয়) */
function rateLimit({ windowMs, max, name }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, 60 * 1000).unref();
  return (req, res, next) => {
    const k = (name || 'rl') + ':' + (req.ip || 'x');
    const now = Date.now();
    let v = hits.get(k);
    if (!v || v.reset <= now) { v = { n: 0, reset: now + windowMs }; hits.set(k, v); }
    v.n++;
    if (v.n > max) {
      return res.status(429).json({ ok: false, code: 'rate', error: 'অনেক বেশি চেষ্টা হয়েছে, একটু পরে আবার করুন', wait: Math.ceil((v.reset - now) / 1000) });
    }
    next();
  };
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = { adminAuth, rateLimit, sha256hex, EMAIL_RE };
