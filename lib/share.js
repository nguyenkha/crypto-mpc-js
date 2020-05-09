const ref = require('ref-napi');
const native = require('./native');

class Share {
  constructor(sharePtr) {
    this.sharePtr = sharePtr;
  }

  free() {
    if (this.sharePtr) {
      native.MPCCrypto_freeShare(this.sharePtr);
      this.sharePtr = null;
    }
  }

  serializePubBIP32() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_serializePubBIP32(this.sharePtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_serializePubBIP32(this.sharePtr, buffer, sizePtr));
    return buffer.readCString();
  }

  getEcdsaPublic() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_getEcdsaPublic(this.sharePtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_getEcdsaPublic(this.sharePtr, buffer, sizePtr));
    return buffer;
  }

  getEddsaPublic() {
    const buffer = Buffer.alloc(32);
    native.checkAndThrowError(native.MPCCrypto_getEddsaPublic(this.sharePtr, buffer));
    return buffer;
  }

  toBuffer() {
    const sizePtr = ref.alloc(native.IntPtr);
    native.checkAndThrowError(native.MPCCrypto_shareToBuf(this.sharePtr, null, sizePtr));
    const buffer = Buffer.alloc(sizePtr.readInt32LE());
    native.checkAndThrowError(native.MPCCrypto_shareToBuf(this.sharePtr, buffer, sizePtr));
    return buffer;
  }

  static fromBuffer(buffer) {
    const sharePtrPtr = ref.alloc(native.VoidPtrPtr);
    native.checkAndThrowError(native.MPCCrypto_shareFromBuf(buffer, buffer.length, sharePtrPtr));
    return new Share(sharePtrPtr.deref());
  }
}

module.exports = Share;
