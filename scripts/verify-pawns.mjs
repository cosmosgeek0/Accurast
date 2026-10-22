// Validate native Pawns envelopes in isolation. No provider API or launcher runs.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const root = path.resolve(process.argv[2]);
const dir = path.join(root, 'var/lib/wdi/companion-apps/pawns-core-20261008');
const source = path.join(root, 'home/ubuntu/grass-single-lead/addons/pawns/20261008');
const fail = code => { throw new Error(code); };
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const read = file => JSON.parse(fs.readFileSync(file));
let keyBytes;
try {
  if (!fs.existsSync(path.join(dir, 'auth-envelope.key'))) fail('PAWNS_ORIGINAL_KEY_MISSING');
  keyBytes = fs.readFileSync(path.join(dir, 'auth-envelope.key'));
  const key = crypto.createPrivateKey(keyBytes);
  const decrypt = ciphertext => crypto.privateDecrypt({key, oaepHash:'sha256',
    padding:crypto.constants.RSA_PKCS1_OAEP_PADDING}, ciphertext);
  const publicFile = path.join(source, 'auth-envelope.pub');
  if (!fs.existsSync(publicFile)) fail('PAWNS_ORIGINAL_PUBLIC_KEY_MISSING');
  const pub = crypto.createPublicKey(fs.readFileSync(publicFile)).export({type:'spki',format:'der'});
  const derived = crypto.createPublicKey(key).export({type:'spki',format:'der'});
  if (!pub.equals(derived)) fail('PAWNS_KEY_PAIR_MISMATCH');
  const accountRaw = decrypt(fs.readFileSync(path.join(source, 'account.encrypted')));
  let account;
  try { account = JSON.parse(accountRaw); } finally { accountRaw.fill(0); }
  if (typeof account.email !== 'string' || !account.email || typeof account.password !== 'string' || !account.password) fail('PAWNS_ACCOUNT_SCHEMA');
  const accountTag = hash(account.email).slice(0,16);
  account.email = ''; account.password = ''; account = null;
  const files = fs.readdirSync(dir).filter(name => name.endsWith('-session.sealed.json')).sort();
  if (!files.length) fail('PAWNS_SAVED_SESSIONS_MISSING');
  let verified=0;
  for (const file of files) {
    if (!/^[0-9]+-session\.sealed\.json$/.test(file)) fail('PAWNS_SESSION_FILENAME_UNRECOGNIZED');
    const job = file.slice(0, -'-session.sealed.json'.length);
    const envelope = read(path.join(dir,file));
    if (envelope.algorithm !== 'RSA-OAEP-SHA256-chunks' || !Array.isArray(envelope.chunks) || !envelope.chunks.length || envelope.chunks.length > 4096) fail('PAWNS_ENVELOPE_SCHEMA');
    if (String(envelope.job_id) !== job || !/^[a-f0-9]{64}$/.test(envelope.plain_sha256 || '')) fail('PAWNS_ENVELOPE_BINDING');
    const chunks = envelope.chunks.map(part => decrypt(Buffer.from(part,'base64')));
    const raw = Buffer.concat(chunks);
    for (const chunk of chunks) chunk.fill(0);
    try {
      if (hash(raw) !== envelope.plain_sha256) fail('PAWNS_SESSION_HASH_MISMATCH');
      const session = JSON.parse(raw);
      const identityFile = path.join(dir, job+'.json');
      if (!fs.existsSync(identityFile)) fail('PAWNS_IDENTITY_MISSING');
      const identity = read(identityFile);
      if (session.device_id !== envelope.device_id || session.device_id !== identity.device_id ||
          String(identity.job_id) !== job || session.account_tag !== identity.account_tag || session.account_tag !== accountTag) fail('PAWNS_SESSION_IDENTITY_ACCOUNT_MISMATCH');
      if (typeof session.access_token !== 'string' || !session.access_token) fail('PAWNS_SESSION_TOKEN_MISSING');
      session.access_token = '';
      verified++;
    } finally { raw.fill(0); }
  }
  console.log(JSON.stringify({ok:true, key_pair_verified:true, account_envelope_decrypted:true,
    saved_sessions_decrypted:verified, identity_account_bindings_verified:verified,
    provider_session_validity_checked:false, mode:'read-only-isolated-no-network'}));
} catch (error) {
  console.error(JSON.stringify({ok:false,error:/^[A-Z_]+$/.test(error.message) ? error.message : 'PAWNS_NATIVE_ENVELOPE_VERIFICATION_FAILED'}));
  process.exitCode=1;
} finally { if(keyBytes) keyBytes.fill(0); }
