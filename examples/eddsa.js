const crypto = require('crypto');
const { Context, utils } = require('..');
const nacl = require('tweetnacl');

console.log('Backup key');
const backupKey = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'der'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'der',
  }
});

console.log('Generate key');
let c1 = Context.createGenerateEddsaKey(1);
let c2 = Context.createGenerateEddsaKey(2);
utils.run(c1, c2);
const k1 = c1.getNewShare();
const k2 = c2.getNewShare();
const publicKey = c1.getPublicKey();
console.log(publicKey.toString('hex'));

console.log('Sign');
const data = Buffer.from('Hello world');
const hash = crypto.createHash('SHA256').update(data).digest();
c1 = Context.createEddsaSignContext(1, k1, hash, false);
c2 = Context.createEddsaSignContext(2, k2, hash, false);
utils.run(c1, c2);
console.log('Signature 1:', c1.getSignature().toString('hex'));
console.log('Signature 2:', c2.getSignature().toString('hex'));
const signature = c1.getSignature();
console.log('Signature:', nacl.sign.detached.verify(hash, signature, publicKey));

c1 = Context.createBackupEddsaKey(1, k1, backupKey.publicKey);
c2 = Context.createBackupEddsaKey(2, k2, backupKey.publicKey);
utils.run(c1, c2);
const backup = c1.getBackup();
console.log('Backup verify:', utils.verifyEddsaBackupKey(backupKey.publicKey, publicKey, backup));
const privateKey = utils.restoreEddsaKey(backupKey.privateKey, publicKey, backup);
const secretKey = Buffer.concat([privateKey, publicKey]);
console.log('Secret key:', secretKey.toString('hex'));
const signature2 = nacl.sign.detached(hash, secretKey);
console.log('Secret verify:', nacl.sign.detached.verify(hash, signature2, publicKey));
