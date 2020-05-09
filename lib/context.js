const ref = require('ref-napi');
const native = require('./native');
const Message = require('./message');
const Share = require('./share');

const Types = {
  GENERATE_GENERIC_SECRET: 0,
  REFRESH: 1,
  DERIVE_BIP32: 2,
  ECDSA_SIGN: 3,
  GENERATE_ECDSA_KEY: 4,
  BACKUP_ECDSA_KEY: 5,
  EDDSA_SIGN: 6,
  GENERATE_EDDSA_KEY: 7,
  BACKUP_EDDSA_KEY: 8,
};

class Context {
  constructor(contextPtr, type) {
    this.contextPtr = contextPtr;
    this.type = type;
    this.finished = false;
    this.changed = false;
  }

  isFinished() {
    return this.finished;
  }

  isChanged() {
    return this.changed;
  }

  step(message) {
    if (this.finished) {
      throw Error('Context finished');
    }
    const input = message ? Message.fromBuffer(message) : null;
    const outputPtrPtr = ref.alloc(native.VoidPtrPtr);
    const flagsPtr = ref.alloc(native.UintPtr);
    native.checkAndThrowError(native.MPCCrypto_step(this.contextPtr, input ? input.messagePtr : null, outputPtrPtr, flagsPtr));
    if (input) {
      input.free();
    }
    const flags = flagsPtr.readUInt32LE();
    this.finished = (flags & native.flags.FINISHED) !== 0;
    this.changed = (flags & native.flags.CHANGED) !== 0;

    if (this.changed) {
      const sharePtrPtr = ref.alloc(native.VoidPtrPtr);
      native.MPCCrypto_getShare(this.contextPtr, sharePtrPtr);
      const share = new Share(sharePtrPtr.deref());
      if (this.type === Types.GENERATE_ECDSA_KEY) {
        this.publicKey = share.getEcdsaPublic();
      }
      if (this.type === Types.GENERATE_EDDSA_KEY) {
        this.publicKey = share.getEddsaPublic();
      }
      this.newShare = share.toBuffer();
      share.free();
    }

    if (this.finished) {
      if (this.type === Types.DERIVE_BIP32) {
        const share = this.getResultDeriveBIP32();
        this.xpub = share.serializePubBIP32();
        this.publicKey = share.getEcdsaPublic();
        this.newShare = share.toBuffer();
        share.free();
      }
      if (this.type === Types.ECDSA_SIGN) {
        this.signature = this.getResultEcdsaSign();
      }
      if (this.type === Types.BACKUP_ECDSA_KEY) {
        this.backup = this.getResultBackupEcdsaKey();
      }
      if (this.type === Types.EDDSA_SIGN) {
        this.signature = this.getResultEddsaSign();
      }
      if (this.type === Types.BACKUP_EDDSA_KEY) {
        this.backup = this.getResultBackupEddsaKey();
      }
      this.free();
    }

    const outputPtr = outputPtrPtr.deref();
    if (outputPtr.isNull()) {
      return null;
    }
    const output = new Message(outputPtr);
    const result = output.toBuffer();
    output.free();
    return result;
  }

  getNewShare() {
    return this.newShare;
  }

  getXpub() {
    return this.xpub;
  }

  getPublicKey() {
    return this.publicKey;
  }

  getSignature() {
    return this.signature;
  }

  getBackup() {
    return this.backup;
  }

  getResultDeriveBIP32() {
    const sharePtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_getResultDeriveBIP32(this.contextPtr, sharePtrPtr));
    return new Share(sharePtrPtr.deref());
  }

  getResultEcdsaSign() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_getResultEcdsaSign(this.contextPtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_getResultEcdsaSign(this.contextPtr, buffer, sizePtr));
    return buffer;
  }

  getResultBackupEcdsaKey() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_getResultBackupEcdsaKey(this.contextPtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_getResultBackupEcdsaKey(this.contextPtr, buffer, sizePtr));
    return buffer;
  }

  getResultEddsaSign() {
    const buffer = Buffer.alloc(64);
    native.checkAndThrowError(native.MPCCrypto_getResultEddsaSign(this.contextPtr, buffer));
    return buffer;
  }

  getResultBackupEddsaKey() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_getResultBackupEddsaKey(this.contextPtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_getResultBackupEddsaKey(this.contextPtr, buffer, sizePtr));
    return buffer;
  }

  toBuffer() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_contextToBuf(this.contextPtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_contextToBuf(this.contextPtr, buffer, sizePtr));
    const typeBuf = Buffer.alloc(1)
    typeBuf.writeUInt8(this.type);
    return Buffer.concat([typeBuf, buffer]);
  }

  free() {
    if (this.contextPtr) {
      native.MPCCrypto_freeContext(this.contextPtr);
      this.contextPtr = null;
    }
  }

  static fromBuffer(buffer) {
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    const type = buffer.readUInt8();
    native.checkAndThrowError(native.MPCCrypto_contextFromBuf(buffer.slice(1), buffer.length - 1, contextPtrPtr));
    return new Context(contextPtrPtr.deref(), type);
  }

  static createGenerateGenericSecretContext(peer, bits) {
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initGenerateGenericSecret(peer, bits, contextPtrPtr));
    return new Context(contextPtrPtr.deref(), Types.GENERATE_GENERIC_SECRET);
  }

  static createDeriveBIP32Context(peer, shareBuf, hardened, index) {
    const share = Share.fromBuffer(shareBuf);
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initDeriveBIP32(peer, share.sharePtr, hardened ? 1 : 0, index, contextPtrPtr));
    share.free();
    return new Context(contextPtrPtr.deref(), Types.DERIVE_BIP32);
  }

  static createEcdsaSignContext(peer, shareBuf, data, refresh) {
    const share = Share.fromBuffer(shareBuf);
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initEcdsaSign(peer, share.sharePtr, data, data.length, refresh ? 1 : 0, contextPtrPtr));
    share.free();
    return new Context(contextPtrPtr.deref(), Types.ECDSA_SIGN);
  }

  static createGenerateEcdsaKey(peer) {
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initGenerateEcdsaKey(peer, contextPtrPtr));
    return new Context(contextPtrPtr.deref(), Types.GENERATE_ECDSA_KEY);
  }

  static createBackupEcdsaKey(peer, shareBuf, backupPublicKey) {
    const share = Share.fromBuffer(shareBuf);
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initBackupEcdsaKey(peer, share.sharePtr, backupPublicKey, backupPublicKey.length, contextPtrPtr));
    share.free();
    return new Context(contextPtrPtr.deref(), Types.BACKUP_ECDSA_KEY);
  }

  static createEddsaSignContext(peer, shareBuf, data, refresh) {
    const share = Share.fromBuffer(shareBuf);
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initEddsaSign(peer, share.sharePtr, data, data.length, refresh ? 1 : 0, contextPtrPtr));
    share.free();
    return new Context(contextPtrPtr.deref(), Types.EDDSA_SIGN);
  }

  static createGenerateEddsaKey(peer) {
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initGenerateEddsaKey(peer, contextPtrPtr));
    return new Context(contextPtrPtr.deref(), Types.GENERATE_EDDSA_KEY);
  }

  static createBackupEddsaKey(peer, shareBuf, backupPublicKey) {
    const share = Share.fromBuffer(shareBuf);
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initBackupEddsaKey(peer, share.sharePtr, backupPublicKey, backupPublicKey.length, contextPtrPtr));
    share.free();
    return new Context(contextPtrPtr.deref(), Types.BACKUP_EDDSA_KEY);
  }

  static createRefreshKey(peer, shareBuf) {
    const share = Share.fromBuffer(shareBuf);
    const contextPtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_initRefreshKey(peer, share.sharePtr, contextPtrPtr));
    share.free();
    return new Context(contextPtrPtr.deref(), Types.REFRESH);
  }
}

module.exports = Context;
