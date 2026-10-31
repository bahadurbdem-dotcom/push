'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const { db, FieldValue } = require('./firebase');
const { sha256hex, EMAIL_RE } = require('./security');
const gmail = require('./gmail');
const push = require('./push');

const pbkdf2 = promisify(crypto.pbkdf2);
const OTP_MIN = 5;          // কোডের মেয়াদ (মিনিট)
const MAX_TRIES = 5;        // ভুল কোডের সর্বোচ্চ সুযোগ
const COOLDOWN_MS = 45000;  // পরপর কোড চাওয়ার ফাঁক
const DAILY_MAX = 10;       // একজনের দিনে সর্বোচ্চ কোড

const fail = (status, code, error, extra) => Object.assign(new Error(error), { status, code, extra });

/* ক্লায়েন্ট অ্যাপের hashPass() এর সাথে হুবহু মিল: pbkdf2$120000$<salt>$<hash> (SHA-256, ৩২ বাইট) */
async function hashPass(p) {
  const salt = crypto.randomBytes(16);
  const h = await pbkdf2(String(p), salt, 120000, 32, 'sha256');
  return 'pbkdf2$120000$' + salt.toString('hex') + '$' + h.toString('hex');
}

async function findUser(email) {
  const q = await db.collection('users').where('login', '==', email).limit(1).get();
  if (q.empty) return null;
  const d = q.docs[0];
  return { id: d.id, ...d.data() };
}

async function send(emailRaw) {
  const email = String(emailRaw || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw fail(400, 'bad_email', 'জিমেইল ঠিক নেই');
  if (!gmail.configured()) throw fail(503, 'off', 'OTP সিস্টেম চালু করা হয়নি');

  const u = await findUser(email);
  if (!u) throw fail(404, 'no_user', 'এই জিমেইলে কোনো অ্যাকাউন্ট নেই');
  if (u.blocked) throw fail(403, 'blocked', 'অ্যাকাউন্ট ব্লক করা আছে');

  const ref = db.collection('otps').doc(u.id);
  const prev = (await ref.get()).data() || {};
  const now = Date.now();
  if (prev.sentAt && now - prev.sentAt < COOLDOWN_MS) {
    throw fail(429, 'wait', 'একটু অপেক্ষা করুন', { wait: Math.ceil((COOLDOWN_MS - (now - prev.sentAt)) / 1000) });
  }
  const sameDay = prev.dayStart && now - prev.dayStart < 86400000;
  const dayCount = sameDay ? (prev.dayCount || 0) : 0;
  if (dayCount >= DAILY_MAX) throw fail(429, 'daily', 'আজকের জন্য কোড চাওয়ার সীমা শেষ, কাল চেষ্টা করুন');

  const otp = String(crypto.randomInt(0, 10000)).padStart(4, '0');
  const salt = crypto.randomBytes(8).toString('hex');
  await ref.set({
    h: sha256hex(otp + salt), salt, email,
    exp: now + OTP_MIN * 60000, tries: 0, sentAt: now,
    dayStart: sameDay ? prev.dayStart : now, dayCount: dayCount + 1
  });

  const settings = await push.getSettings();
  const store = settings.storeName || process.env.STORE_NAME || 'IS Fashion';

  // ইমেইল (জরুরি) ও পুশ (বাড়তি) একসাথে
  const mail = gmail.otpMail({ store, name: u.name || '', otp, minutes: OTP_MIN });
  const [mailRes, pushRes] = await Promise.allSettled([
    gmail.sendMail({ to: email, subject: mail.subject, text: mail.text, html: mail.html, fromName: store }),
    push.pushOtp(u.id, otp, OTP_MIN)
  ]);
  if (mailRes.status === 'rejected') {
    console.error('[otp] mail error:', mailRes.reason && mailRes.reason.message);
    await ref.delete().catch(() => {});
    throw fail(502, 'mail_failed', 'ইমেইল পাঠানো যায়নি, একটু পরে আবার চেষ্টা করুন');
  }
  const pushed = pushRes.status === 'fulfilled' && pushRes.value > 0;
  return { ok: true, pushed, minutes: OTP_MIN };
}

async function reset(emailRaw, otpRaw, password) {
  const email = String(emailRaw || '').trim().toLowerCase();
  const otp = String(otpRaw || '').trim();
  password = String(password || '');
  if (!EMAIL_RE.test(email)) throw fail(400, 'bad_email', 'জিমেইল ঠিক নেই');
  if (!/^\d{4}$/.test(otp)) throw fail(400, 'bad_code', 'কোড ৪ সংখ্যার হতে হবে');
  if (password.length < 6 || password.length > 200) throw fail(400, 'weak_pass', 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে');

  const u = await findUser(email);
  if (!u) throw fail(404, 'no_user', 'এই জিমেইলে কোনো অ্যাকাউন্ট নেই');
  if (u.blocked) throw fail(403, 'blocked', 'অ্যাকাউন্ট ব্লক করা আছে');

  const ref = db.collection('otps').doc(u.id);
  // যাচাই transaction এ — যাতে একসাথে অনেক অনুমান চালিয়ে ৫ বারের সীমা পার করা না যায়
  const verdict = await db.runTransaction(async (tx) => {
    const s = await tx.get(ref);
    if (!s.exists) return 'expired';
    const o = s.data();
    if (Date.now() > o.exp) return 'expired';
    if ((o.tries || 0) >= MAX_TRIES) return 'too_many';
    const given = Buffer.from(sha256hex(otp + o.salt));
    const want = Buffer.from(String(o.h));
    const okCode = given.length === want.length && crypto.timingSafeEqual(given, want);
    if (!okCode) { tx.update(ref, { tries: FieldValue.increment(1) }); return { bad: MAX_TRIES - (o.tries || 0) - 1 }; }
    tx.delete(ref);
    return 'ok';
  });

  if (verdict === 'expired') throw fail(410, 'expired', 'কোডের সময় শেষ। নতুন কোড নিন।');
  if (verdict === 'too_many') throw fail(429, 'too_many', 'অনেকবার ভুল হয়েছে। নতুন কোড নিন।');
  if (verdict !== 'ok') throw fail(400, 'bad_code', 'কোড ভুল হয়েছে', { left: verdict.bad });

  await db.collection('users').doc(u.id).update({ pass: await hashPass(password), pw: FieldValue.delete() });
  return { ok: true, uid: u.id };
}

async function test(emailRaw) {
  const email = String(emailRaw || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw fail(400, 'bad_email', 'জিমেইল ঠিক নেই');
  if (!gmail.configured()) throw fail(503, 'off', 'Gmail সেট করা নেই (GMAIL_* এনভায়রনমেন্ট ভ্যারিয়েবল দেখুন)');
  const settings = await push.getSettings();
  const store = settings.storeName || process.env.STORE_NAME || 'IS Fashion';
  const m = gmail.otpMail({ store, name: 'পরীক্ষা', otp: '1234', minutes: OTP_MIN });
  await gmail.sendMail({ to: email, subject: m.subject, text: m.text, html: m.html, fromName: store });
  return { ok: true };
}

module.exports = { send, reset, test, hashPass };
