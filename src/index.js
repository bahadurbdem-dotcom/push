'use strict';
const express = require('express');
const cors = require('cors');
const { adminAuth, rateLimit } = require('./security');

let fb;
try { fb = require('./firebase'); }
catch (e) { console.error('❌ ' + e.message); process.exit(1); }

const push = require('./push');
const otp = require('./otp');
const gmail = require('./gmail');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, !allowed.length || !origin || allowed.includes(origin)),
  allowedHeaders: ['Content-Type', 'x-admin-key'],
  methods: ['GET', 'POST', 'OPTIONS'],
  maxAge: 86400
}));
app.use(express.json({ limit: '20kb' }));

const wrap = (fn) => async (req, res) => {
  try { res.json(await fn(req)); }
  catch (e) {
    const status = e.status || 500;
    if (status >= 500) console.error('[error]', req.path, e.message);
    res.status(status).json({ ok: false, code: e.code || 'error', error: status >= 500 && !e.code ? 'সার্ভারে সমস্যা হয়েছে' : e.message, ...(e.extra || {}) });
  }
};

/* ---------- স্বাস্থ্য ---------- */
const health = (req, res) => res.json({ ok: true, service: 'is-fashion-server', time: Date.now() });
app.get('/', health);
app.get('/health', health);

/* ---------- পুশ ---------- */
app.post('/api/push/register', rateLimit({ windowMs: 60000, max: 30, name: 'reg' }), wrap(async (req) => {
  if (!(await push.masterOn())) return { ok: true, skipped: 'master_off' };
  await push.registerToken({ token: req.body.token, uid: req.body.uid, ua: req.body.ua });
  return { ok: true };
}));
app.post('/api/push/unregister', rateLimit({ windowMs: 60000, max: 30, name: 'unreg' }), wrap(async (req) => {
  await push.unregisterToken(req.body.token); return { ok: true };
}));
app.post('/api/push/dispatch', adminAuth, wrap((req) => push.dispatch(req.body.id, !!req.body.force)));

/* ---------- অ্যাডমিন: অবস্থা ও পরীক্ষা ---------- */
app.get('/api/admin/status', adminAuth, wrap(async () => ({
  ok: true,
  firebase: fb.projectId,
  pushMaster: await push.masterOn(true),
  gmailConfigured: gmail.configured(),
  gmailUser: gmail.configured() ? gmail.user() : '',
  ...(await push.stats())
})));
app.post('/api/otp/test', adminAuth, rateLimit({ windowMs: 60000, max: 5, name: 'otptest' }), wrap((req) => otp.test(req.body.email)));

/* ---------- OTP ---------- */
app.post('/api/otp/send', rateLimit({ windowMs: 10 * 60000, max: 15, name: 'otpsend' }), wrap((req) => otp.send(req.body.email)));
app.post('/api/otp/reset', rateLimit({ windowMs: 10 * 60000, max: 30, name: 'otpreset' }), wrap((req) => otp.reset(req.body.email, req.body.otp, req.body.password)));

app.use((req, res) => res.status(404).json({ ok: false, error: 'পাওয়া যায়নি' }));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('✅ IS Fashion সার্ভার চালু, পোর্ট ' + PORT + ' | Firebase: ' + fb.projectId +
    ' | Gmail: ' + (gmail.configured() ? 'সেট' : 'সেট নেই') + ' | ADMIN_KEY: ' + ((process.env.ADMIN_KEY || '').length >= 16 ? 'সেট' : 'সেট নেই'));
});
