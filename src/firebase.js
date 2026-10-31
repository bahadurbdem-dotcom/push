'use strict';
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

function loadServiceAccount() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (raw && raw.trim()) {
    const txt = raw.trim().startsWith('{') ? raw.trim() : Buffer.from(raw.trim(), 'base64').toString('utf8');
    try { return JSON.parse(txt); }
    catch (e) { throw new Error('FIREBASE_SERVICE_ACCOUNT এর JSON ঠিক নেই: ' + e.message); }
  }
  const files = ['/etc/secrets/serviceAccountKey.json', path.join(__dirname, '..', 'serviceAccountKey.json')];
  for (const f of files) {
    if (fs.existsSync(f)) {
      try { return JSON.parse(fs.readFileSync(f, 'utf8')); }
      catch (e) { throw new Error(f + ' ফাইলের JSON ঠিক নেই: ' + e.message); }
    }
  }
  throw new Error('Firebase Service Account পাওয়া যায়নি। Render এ Secret File (serviceAccountKey.json) যোগ করুন।');
}

const sa = loadServiceAccount();
admin.initializeApp({ credential: admin.credential.cert(sa) });

module.exports = {
  admin,
  db: admin.firestore(),
  FieldValue: admin.firestore.FieldValue,
  projectId: sa.project_id
};
