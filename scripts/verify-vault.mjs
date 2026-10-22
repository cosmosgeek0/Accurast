// Read-only validation: do not instantiate the live vault or acquire/release its locks.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const root = path.resolve(process.argv[2]);
const base = path.join(root, 'var/lib/wdi-acurast-manager');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const read = p => JSON.parse(fs.readFileSync(p));
const fail = code => { throw new Error(code); };
function unseal(key, envelope, aad) {
  if (envelope.v !== 1) fail('ENVELOPE_VERSION');
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  d.setAAD(Buffer.from(aad)); d.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const raw = Buffer.concat([d.update(Buffer.from(envelope.ciphertext, 'base64')), d.final()]);
  try { return JSON.parse(raw); } finally { raw.fill(0); }
}
let key;
try {
  const wrapped = read(path.join(base, 'vault/key.json'));
  if (wrapped.format !== 'rsa-oaep-sha256') fail('KEY_WRAP_FORMAT');
  key = crypto.privateDecrypt({key: fs.readFileSync(path.join(base, 'transfer-private.pem')),
    oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, Buffer.from(wrapped.key, 'base64'));
  if (key.length !== 32) fail('VAULT_KEY_LENGTH');
  const registry = unseal(key, read(path.join(base, 'vault/registry.json')), 'grass-ip-registry-v1');
  if (registry.format !== 'ip-identity-v1' || !registry.entries || !/^[a-f0-9]{64}$/.test(registry.accountHash)) fail('REGISTRY_FORMAT');
  const identities = new Map(), privateKeys = new Map();
  let profiles = 0, references = 0, quarantined = 0, leases = 0, pending = 0;
  const objects = new Set();
  for (const [profileKey, entry] of Object.entries(registry.entries)) {
    if (entry.quarantined) quarantined++;
    if (entry.lease) leases++;
    if (!entry.object) { pending++; continue; }
    if (!/^[a-f0-9]{64}$/.test(entry.object)) fail('OBJECT_ID');
    const objectFile = path.join(base, 'vault/objects', entry.object + '.json');
    if (!fs.existsSync(objectFile)) fail('CURRENT_OBJECT_MISSING');
    const raw = fs.readFileSync(objectFile);
    if (hash(raw) !== entry.object) fail('OBJECT_HASH');
    const profile = unseal(key, JSON.parse(raw), 'grass-profile-v1:' + profileKey);
    const native = profile.format === 'grass-native-state-v1';
    if (!native && profile.format !== 'grass-official-state-v1') fail('PROFILE_FORMAT');
    if (!Array.isArray(profile.files)) fail('PROFILE_FILES');
    const files = new Map();
    for (const f of profile.files) {
      if (files.has(f.path) || typeof f.data !== 'string') fail('PROFILE_DUPLICATE_FILE');
      files.set(f.path, Buffer.from(f.data, 'base64'));
    }
    const required = native ? ['device_identity.json'] : ['store.json', 'grass-sdk/device_identity', 'grass-sdk/consent', 'grass-sdk/sharing'];
    if (required.some(p => !files.has(p))) fail('PROFILE_REQUIRED_FILE');
    const identity = JSON.parse(files.get(native ? 'device_identity.json' : 'grass-sdk/device_identity'));
    if (typeof identity.device_id !== 'string' || !identity.device_id || typeof identity.user_id !== 'string' || !identity.user_id) fail('IDENTITY_FORMAT');
    if (!Array.isArray(identity.private_key) || identity.private_key.length !== 32 || !identity.private_key.every(x => Number.isInteger(x) && x >= 0 && x <= 255)) fail('IDENTITY_KEY_FORMAT');
    if (hash(identity.user_id) !== registry.accountHash) fail('PROFILE_ACCOUNT_MISMATCH');
    if (!native) {
      const store = JSON.parse(files.get('store.json'));
      const decode = v => { try { return typeof v === 'string' ? JSON.parse(v) : v; } catch { return v; } };
      if (decode(store['wynd:user_id']) !== identity.user_id || decode(store['wynd:device_id']) !== identity.device_id || decode(store['wynd:authenticated']) !== true) fail('STORE_IDENTITY_MISMATCH');
    }
    const deviceHash = hash(identity.device_id), keyHash = hash(Buffer.from(identity.private_key));
    if (deviceHash !== entry.deviceHash || keyHash !== entry.keyHash) fail('PROFILE_REGISTRY_IDENTITY_MISMATCH');
    if (identities.has(deviceHash) || privateKeys.has(keyHash)) fail('DUPLICATE_CANONICAL_IDENTITY');
    identities.set(deviceHash, profileKey); privateKeys.set(keyHash, profileKey);
    if (!profile.binding || !/^[a-f0-9]{64}$/.test(profile.binding.binarySha256 || '')) fail('PROFILE_BINARY_BINDING');
    if (JSON.stringify(profile.binding) !== JSON.stringify(entry.binding)) fail('REGISTRY_BINDING_MISMATCH');
    const stateHash = hash(JSON.stringify({binding: profile.binding, files: [...profile.files].sort((a,b) => a.path.localeCompare(b.path))}));
    if (entry.stateHash && stateHash !== entry.stateHash) fail('PROFILE_STATE_HASH');
    objects.add(entry.object); profiles++; references++;
    for (const b of files.values()) b.fill(0);
  }
  // Historical references need to survive even when an old identity has moved.
  function historyWalk(value) {
    if (!value || typeof value !== 'object') return;
    for (const [name, child] of Object.entries(value)) {
      if (name === 'object' && typeof child === 'string' && /^[a-f0-9]{64}$/.test(child)) {
        const historicalFile = path.join(base, 'vault/objects', child + '.json');
        if (!fs.existsSync(historicalFile)) fail('HISTORICAL_OBJECT_MISSING');
        const raw = fs.readFileSync(historicalFile);
        if (hash(raw) !== child) fail('HISTORICAL_OBJECT_HASH');
        objects.add(child); references++;
      } else if (child && typeof child === 'object') historyWalk(child);
    }
  }
  for (const entry of Object.values(registry.entries)) historyWalk(entry.previousBindings);
  console.log(JSON.stringify({ok:true, registry_entries:Object.keys(registry.entries).length,
    profiles_verified:profiles, unique_objects_verified:objects.size, object_references:references,
    pending_without_profile:pending, preserved_leases:leases, preserved_quarantines:quarantined,
    registry_revision:registry.revision, registry_fence:registry.fence, mode:'read-only-isolated'}));
} catch (e) {
  // Never emit profile values, keys, exception stacks or library error data.
  console.error(JSON.stringify({ok:false, error:/^[A-Z_]+$/.test(e.message) ? e.message : 'VAULT_VERIFICATION_FAILED'}));
  process.exitCode=1;
} finally { if (key) key.fill(0); }
