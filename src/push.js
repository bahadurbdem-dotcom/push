'use strict';
const { admin, db, FieldValue } = require('./firebase');
const { sha256hex } = require('./security');

const TOKENS = () => db.collection('push_tokens');

/* ---------- সেটিংস (settings/main) — ১০ সেকেন্ড ক্যাশ ---------- */
let sCache = { t: 0, v: {} };
async function getSettings(fresh) {
  if (!fresh && Date.now() - sCache.t < 10000) return sCache.v;
  const d = await db.collection('settings').doc('main').get();
  sCache = { t: Date.now(), v: d.exists ? d.data() : {} };
  return sCache.v;
}
const masterOn = async (fresh) => (await getSettings(fresh)).pushEnabled === true;

/* ---------- টোকেন রেজিস্টার / আনরেজিস্টার ---------- */
async function registerToken({ token, uid, ua }) {
  token = String(token || '');
  if (token.length < 50 || token.length > 4096) { const e = new Error('টোকেন ঠিক নেই'); e.status = 400; e.code = 'bad_token'; throw e; }
  uid = uid ? String(uid).slice(0, 128) : null;
  if (uid) {
    const u = await db.collection('users').doc(uid).get();
    if (!u.exists) uid = null;
  }
  const ref = TOKENS().doc(sha256hex(token).slice(0, 40));
  const snap = await ref.get();
  const prev = snap.exists ? snap.data() : {};
  const data = {
    token,
    uid: uid || null,
    lastUid: uid || prev.lastUid || null,
    ua: String(ua || '').slice(0, 200),
    updatedAt: Date.now()
  };
  if (!snap.exists) data.createdAt = Date.now();
  await ref.set(data, { merge: true });
  return true;
}
async function unregisterToken(token) {
  token = String(token || '');
  if (!token) return;
  await TOKENS().doc(sha256hex(token).slice(0, 40)).delete().catch(() => {});
}

/* ---------- পাঠানো ---------- */
async function tokenDocs(target, field) {
  if (target === 'all') return (await TOKENS().get()).docs;
  return (await TOKENS().where(field || 'uid', '==', target).get()).docs;
}

const clip = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const safeHttps = (u) => (/^https:\/\/[^\s]{4,480}$/.test(String(u || '')) ? String(u) : '');

async function sendToDocs(docs, data) {
  let ok = 0, fail = 0;
  const dead = [];
  for (let i = 0; i < docs.length; i += 500) {
    const chunk = docs.slice(i, i + 500);
    const res = await admin.messaging().sendEachForMulticast({
      tokens: chunk.map((d) => d.data().token),
      data,
      android: { priority: 'high', ttl: 86400000 },
      webpush: { headers: { Urgency: 'high', TTL: '86400' } }
    });
    ok += res.successCount; fail += res.failureCount;
    res.responses.forEach((r, k) => {
      if (!r.success) {
        const c = r.error && r.error.code;
        if (c === 'messaging/registration-token-not-registered' || c === 'messaging/invalid-registration-token' || c === 'messaging/invalid-argument') dead.push(chunk[k].ref);
      }
    });
  }
  if (dead.length) {
    for (let i = 0; i < dead.length; i += 400) {
      const b = db.batch(); dead.slice(i, i + 400).forEach((r) => b.delete(r)); await b.commit().catch(() => {});
    }
  }
  return { ok, fail, removed: dead.length };
}

/* notifications/{id} ডকুমেন্ট পুশ করা — এডমিন-লেখা ও সিস্টেম-লেখা, দুটোই এই এক পথে */
async function dispatch(id, force) {
  id = String(id || '');
  if (!/^[A-Za-z0-9_-]{3,100}$/.test(id)) { const e = new Error('নোটিফিকেশন আইডি ঠিক নেই'); e.status = 400; throw e; }
  const ref = db.collection('notifications').doc(id);

  if (!(await masterOn(true))) {
    await ref.set({ pushState: 'master_off' }, { merge: true }).catch(() => {});
    return { ok: true, skipped: 'master_off', sent: 0 };
  }

  // একবারই পাঠানোর জন্য "দখল" (transaction)
  const claim = await db.runTransaction(async (tx) => {
    const s = await tx.get(ref);
    if (!s.exists) return { err: 'not_found' };
    const n = s.data();
    if (n.push === false) return { skip: 'push_off' };
    const st = n.pushState;
    const stale = st === 'sending' && Date.now() - (n.pushAt || 0) > 120000;
    if (!force && (st === 'sent' || (st === 'sending' && !stale))) return { skip: 'already', n };
    tx.set(ref, { pushState: 'sending', pushAt: Date.now() }, { merge: true });
    return { n };
  });
  if (claim.err) { const e = new Error('নোটিফিকেশন পাওয়া যায়নি'); e.status = 404; throw e; }
  if (claim.skip) return { ok: true, skipped: claim.skip, sent: 0 };

  const n = claim.n;
  const to = !n.to || n.to === 'all' ? 'all' : String(n.to);
  const docs = await tokenDocs(to, 'uid');
  const settings = await getSettings();
  const body = n.text ? n.text : (n.html ? 'দেখতে ট্যাপ করুন' : '');
  const data = {
    type: 'notif',
    notifId: id,
    title: clip(n.title || settings.storeName || 'নোটিফিকেশন', 100),
    body: clip(body, 200)
  };
  const img = safeHttps(n.image); if (img) data.image = img;
  const ic = safeHttps(settings.logoUrl); if (ic) data.icon = ic;

  let r = { ok: 0, fail: 0, removed: 0 };
  try {
    if (docs.length) r = await sendToDocs(docs, data);
  } catch (e) {
    await ref.set({ pushState: 'error', pushError: clip(e.message, 200), pushAt: Date.now() }, { merge: true }).catch(() => {});
    throw e;
  }
  await ref.set({ pushState: 'sent', pushAt: Date.now(), pushCount: r.ok, pushFail: r.fail }, { merge: true });
  return { ok: true, sent: r.ok, failed: r.fail, devices: docs.length, removed: r.removed };
}

/* OTP পুশ — ইউজারের আগের ডিভাইসগুলোতে (lastUid) */
async function pushOtp(uid, otp, minutes) {
  if (!(await masterOn())) return 0;
  const docs = await tokenDocs(uid, 'lastUid');
  if (!docs.length) return 0;
  const r = await sendToDocs(docs, {
    type: 'otp',
    title: 'পাসওয়ার্ড রিসেট কোড',
    body: 'আপনার কোড: ' + otp + ' (' + minutes + ' মিনিট কাজ করবে)',
    notifId: 'otp'
  });
  return r.ok;
}

async function stats() {
  const snap = await TOKENS().get();
  let guests = 0, users = 0;
  snap.forEach((d) => { d.data().uid ? users++ : guests++; });
  return { devices: snap.size, loggedIn: users, guests };
}

module.exports = { registerToken, unregisterToken, dispatch, pushOtp, stats, masterOn, getSettings };
