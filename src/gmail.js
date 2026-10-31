'use strict';
/* Gmail API (HTTPS) দিয়ে ইমেইল পাঠানো।
   কেন SMTP নয়: Render ফ্রি সার্ভারে SMTP পোর্ট (25/465/587) বন্ধ। Gmail API সাধারণ HTTPS (443) ব্যবহার করে, তাই চলে।
   মেইল সরাসরি আপনার নিজের Gmail থেকে যায় (Google এর SPF/DKIM সহ) — তাই ইনবক্সে পৌঁছানোর সম্ভাবনা সবচেয়ে বেশি। */

const cfg = () => ({
  user: (process.env.GMAIL_USER || '').trim(),
  id: (process.env.GMAIL_CLIENT_ID || '').trim(),
  secret: (process.env.GMAIL_CLIENT_SECRET || '').trim(),
  refresh: (process.env.GMAIL_REFRESH_TOKEN || '').trim()
});
const configured = () => { const c = cfg(); return !!(c.user && c.id && c.secret && c.refresh); };

let cache = { token: null, exp: 0 };

async function timedFetch(url, opts, ms) {
  const ac = new AbortController();
  const tm = setTimeout(() => ac.abort(), ms || 15000);
  try { return await fetch(url, { ...opts, signal: ac.signal }); }
  finally { clearTimeout(tm); }
}

async function accessToken() {
  if (cache.token && cache.exp > Date.now() + 60000) return cache.token;
  const c = cfg();
  const r = await timedFetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: c.id, client_secret: c.secret, refresh_token: c.refresh, grant_type: 'refresh_token'
    }).toString()
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    const code = j.error || r.status;
    const hint = code === 'invalid_grant'
      ? ' (Refresh Token মেয়াদ শেষ/বাতিল — OAuth consent screen "In production" করা আছে কিনা দেখুন, তারপর নতুন Refresh Token নিন)'
      : '';
    throw new Error('Gmail টোকেন পাওয়া যায়নি: ' + code + (j.error_description ? ' - ' + j.error_description : '') + hint);
  }
  cache = { token: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3000) * 1000 };
  return cache.token;
}

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const encWord = (s) => '=?UTF-8?B?' + Buffer.from(String(s), 'utf8').toString('base64') + '?=';
const wrap76 = (b64) => b64.replace(/(.{76})/g, '$1\r\n');
const cleanHeader = (s) => String(s || '').replace(/[\r\n]+/g, ' ').trim();

function buildMime({ fromName, fromEmail, to, subject, text, html }) {
  const boundary = 'b_' + Date.now().toString(36) + Math.random().toString(36).slice(2);
  const part = (type, body) =>
    '--' + boundary + '\r\nContent-Type: ' + type + '; charset="UTF-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
    wrap76(Buffer.from(body, 'utf8').toString('base64')) + '\r\n';
  return [
    'From: ' + encWord(cleanHeader(fromName)) + ' <' + cleanHeader(fromEmail) + '>',
    'To: ' + cleanHeader(to),
    'Subject: ' + encWord(cleanHeader(subject)),
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="' + boundary + '"',
    '',
    part('text/plain', text) + part('text/html', html) + '--' + boundary + '--',
    ''
  ].join('\r\n');
}

async function sendMail({ to, subject, text, html, fromName }) {
  if (!configured()) { const e = new Error('Gmail সেট করা নেই'); e.code = 'off'; throw e; }
  const c = cfg();
  const token = await accessToken();
  const raw = b64url(buildMime({ fromName: fromName || process.env.STORE_NAME || 'IS Fashion', fromEmail: c.user, to, subject, text, html }));
  const r = await timedFetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw })
  }, 20000);
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    if (r.status === 401) cache = { token: null, exp: 0 };
    throw new Error('Gmail পাঠাতে ব্যর্থ (' + r.status + '): ' + t.slice(0, 200));
  }
  return true;
}

/* OTP মেইলের ডিজাইন: ছোট, লিংকহীন (স্প্যাম ফিল্টার এড়াতে), সাথে সাধারণ টেক্সট ভার্সন */
function otpMail({ store, name, otp, minutes }) {
  const text =
    store + ' — পাসওয়ার্ড রিসেট কোড\n\n' +
    (name ? 'হ্যালো ' + name + ',\n\n' : '') +
    'আপনার ৪ সংখ্যার কোড: ' + otp + '\n' +
    'কোডটি ' + minutes + ' মিনিট পর্যন্ত কাজ করবে। কাউকে এই কোড বলবেন না।\n\n' +
    'আপনি অনুরোধ না করলে এই মেইল উপেক্ষা করুন।';
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;max-width:420px;margin:0 auto;padding:24px;color:#222">' +
    '<h2 style="margin:0 0 12px;font-size:18px">' + esc(store) + '</h2>' +
    (name ? '<p style="margin:0 0 12px">হ্যালো ' + esc(name) + ',</p>' : '') +
    '<p style="margin:0 0 12px">আপনার পাসওয়ার্ড রিসেট কোড:</p>' +
    '<div style="font-size:34px;font-weight:700;letter-spacing:10px;text-align:center;background:#f4f4f5;border-radius:10px;padding:16px 0;margin:0 0 14px">' + esc(otp) + '</div>' +
    '<p style="margin:0 0 8px;font-size:14px">কোডটি ' + minutes + ' মিনিট পর্যন্ত কাজ করবে। কাউকে এই কোড বলবেন না।</p>' +
    '<p style="margin:0;font-size:12px;color:#777">আপনি অনুরোধ না করলে এই মেইল উপেক্ষা করুন।</p></div>';
  return { subject: store + ' — আপনার কোড ' + otp, text, html };
}

module.exports = { configured, sendMail, otpMail, buildMime, user: () => cfg().user };
