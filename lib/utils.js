const native = require('./native');
const ref = require('ref');

function verifyEcdsaBackupKey(backupPublicKey, publicKey, backup) {
  return native.MPCCrypto_verifyEcdsaBackupKey(backupPublicKey, backupPublicKey.length, publicKey, publicKey.length, backup, backup.length) === 0;
}

function restoreEcdsaKey(backupPrivateKey, publicKey, backup) {
  const sizePtr = ref.alloc(native.IntPtr);
  native.checkAndThrowError(native.MPCCrypto_restoreEcdsaKey(backupPrivateKey, backupPrivateKey.length, publicKey, publicKey.length, backup, backup.length, null, sizePtr));
  const privateKey = Buffer.alloc(sizePtr.readInt32LE());
  native.checkAndThrowError(native.MPCCrypto_restoreEcdsaKey(backupPrivateKey, backupPrivateKey.length, publicKey, publicKey.length, backup, backup.length, privateKey, sizePtr));
  return privateKey;
}

function verifyEddsaBackupKey(backupPublicKey, publicKey, backup) {
  return native.MPCCrypto_verifyEddsaBackupKey(backupPublicKey, backupPublicKey.length, publicKey, backup, backup.length) === 0;
}

function restoreEddsaKey(backupPrivateKey, publicKey, backup) {
  const privateKey = Buffer.alloc(32);
  native.checkAndThrowError(native.MPCCrypto_restoreEddsaKey(backupPrivateKey, backupPrivateKey.length, publicKey, backup, backup.length, privateKey));
  return privateKey;
}

function run(c1, c2) {
  let m;
  while (!c1.isFinished() || !c2.isFinished()) {
    if (!c1.isFinished()) {
      m = c1.step(m);
    }
    if (!m) {
      break;
    }
    if (!c2.isFinished()) {
      m = c2.step(m);
    }
  }
}

module.exports = {
  run,
  verifyEcdsaBackupKey,
  restoreEcdsaKey,
  verifyEddsaBackupKey,
  restoreEddsaKey,
};