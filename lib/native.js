const ffi = require('ffi');
const ref = require('ref');
const path = require('path');

const IntPtr = ref.refType(ref.types.int);
const Uint8Ptr = ref.refType(ref.types.uint8);
const UintPtr = ref.refType(ref.types.uint);
const VoidPtr = ref.refType(ref.types.void);
const VoidPtrPtr = ref.refType(VoidPtr);

const errorCodes = {
  MPC_E_BADARG: 0xff010002,
  MPC_E_FORMAT: 0xff010003,
  MPC_E_TOO_SMALL: 0xff010008,
  MPC_E_CRYPTO: 0xff040001,
};

// Copy from mpc_crypto.h

const mpc = ffi.Library(path.join(__dirname, '..', 'deps', 'MPCCrypto'), {
  // Memory management 
  // MPCCRYPTO_API void MPCCrypto_freeShare(MPCCryptoShare * share);
  MPCCrypto_freeShare: [ref.types.void, [VoidPtr]],

  // MPCCRYPTO_API void MPCCrypto_freeContext(MPCCryptoContext * context);
  MPCCrypto_freeContext: [ref.types.void, [VoidPtr]],

  // MPCCRYPTO_API void MPCCrypto_freeMessage(MPCCryptoMessage * message);
  MPCCrypto_freeMessage: [ref.types.void, [VoidPtr]],

  // Serialization
  // MPCCRYPTO_API int MPCCrypto_shareToBuf(MPCCryptoShare * share, uint8_t * out, int * out_size);
  MPCCrypto_shareToBuf: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],

  // MPCCRYPTO_API int MPCCrypto_contextToBuf(MPCCryptoContext * context, uint8_t * out, int * out_size);
  MPCCrypto_contextToBuf: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],

  // MPCCRYPTO_API int MPCCrypto_messageToBuf(MPCCryptoMessage * message, uint8_t * out, int * out_size);
  MPCCrypto_messageToBuf: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],

  // Deserialization
  // MPCCRYPTO_API int MPCCrypto_shareFromBuf(const uint8_t* in, int in_size, MPCCryptoShare ** share);
  MPCCrypto_shareFromBuf: [ref.types.int, [Uint8Ptr, ref.types.int, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_contextFromBuf(const uint8_t* in, int in_size, MPCCryptoContext ** context);
  MPCCrypto_contextFromBuf: [ref.types.int, [Uint8Ptr, ref.types.int, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_messageFromBuf(const uint8_t* in, int in_size, MPCCryptoMessage ** message);
  MPCCrypto_messageFromBuf: [ref.types.int, [Uint8Ptr, ref.types.int, VoidPtrPtr]],

  // Information
  // MPCCRYPTO_API int MPCCrypto_shareInfo(MPCCryptoShare * share, mpc_crypto_share_info_t * info);
  // MPCCRYPTO_API int MPCCrypto_contextInfo(MPCCryptoContext * context, mpc_crypto_context_info_t * info);
  // MPCCRYPTO_API int MPCCrypto_messageInfo(MPCCryptoMessage * message, mpc_crypto_message_info_t * info);

  // Run a single step in the process on one of the peers	
  // MPCCRYPTO_API int MPCCrypto_step(MPCCryptoContext * context, MPCCryptoMessage * in, MPCCryptoMessage ** out, unsigned * flags);
  MPCCrypto_step: [ref.types.int, [VoidPtr, VoidPtr, VoidPtrPtr, UintPtr]],

  // Get key share from the context (in case of an updated key share)
  // MPCCRYPTO_API int MPCCrypto_getShare(MPCCryptoContext * context, MPCCryptoShare ** share);
  MPCCrypto_getShare: [ref.types.void, [VoidPtr, VoidPtrPtr]],

  // Refresh
  // MPCCRYPTO_API int MPCCrypto_initRefreshKey(int peer, MPCCryptoShare * share, MPCCryptoContext ** context);
  MPCCrypto_initRefreshKey: [ref.types.int, [ref.types.int, VoidPtr, VoidPtrPtr]],

  // EdDSA specific functions
  // MPCCRYPTO_API int MPCCrypto_initGenerateEddsaKey(int peer, MPCCryptoContext ** context);
  MPCCrypto_initGenerateEddsaKey: [ref.types.int, [ref.types.int, VoidPtrPtr]],
  // MPCCRYPTO_API int MPCCrypto_initEddsaSign(int peer, MPCCryptoShare * share, const uint8_t* in, int in_size, int refresh, MPCCryptoContext ** context);
  MPCCrypto_initEddsaSign: [ref.types.int, [ref.types.int, VoidPtr, Uint8Ptr, ref.types.int, ref.types.int, VoidPtrPtr]],
  // MPCCRYPTO_API int MPCCrypto_getResultEddsaSign(MPCCryptoContext * context, uint8_t * signature); // |signature|=64
  MPCCrypto_getResultEddsaSign: [ref.types.int, [VoidPtr, Uint8Ptr]],
  // MPCCRYPTO_API int MPCCrypto_verifyEddsa(const uint8_t* pub_key, const uint8_t* in, int in_size, const uint8_t* signature); // |pub_key|=32, |signature|=64
  MPCCrypto_verifyEddsa: [ref.types.int, [Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int, Uint8Ptr]],
  // MPCCRYPTO_API int MPCCrypto_getEddsaPublic(MPCCryptoShare * share, uint8_t * pub_key); // |pub_key|=32
  MPCCrypto_getEddsaPublic: [ref.types.int, [VoidPtr, Uint8Ptr]],

  // ECDSA specific functions
  // MPCCRYPTO_API int MPCCrypto_initGenerateEcdsaKey(int peer, MPCCryptoContext ** context);
  MPCCrypto_initGenerateEcdsaKey: [ref.types.int, [ref.types.int, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_initEcdsaSign(int peer, MPCCryptoShare * share, const uint8_t* in, int in_size, int refresh, MPCCryptoContext ** context);
  MPCCrypto_initEcdsaSign: [ref.types.int, [ref.types.int, VoidPtr, Uint8Ptr, ref.types.int, ref.types.int, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_getResultEcdsaSign(MPCCryptoContext * context, uint8_t * signature, int * out_size); // signature is der-encoded
  MPCCrypto_getResultEcdsaSign: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],

  // MPCCRYPTO_API int MPCCrypto_verifyEcdsa(const uint8_t* pub_key, int pub_key_size, const uint8_t* in, int in_size, const uint8_t* signature, int signature_size);
  MPCCrypto_verifyEcdsa: [ref.types.int, [Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int]],
  
  // MPCCRYPTO_API int MPCCrypto_getEcdsaPublic(MPCCryptoShare * share, uint8_t * pub_key, int * pub_key_size);
  MPCCrypto_getEcdsaPublic: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],

  // Generic secret (seed) functions
  // MPCCRYPTO_API int MPCCrypto_initGenerateGenericSecret(int peer, int bits, MPCCryptoContext ** context);
  MPCCrypto_initGenerateGenericSecret: [ref.types.int, [ref.types.int, ref.types.int, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_initImportGenericSecret(int peer, const uint8_t* key, int size, MPCCryptoContext ** context);
  MPCCrypto_initImportGenericSecret: [ref.types.int, [ref.types.int, Uint8Ptr, ref.types.int, VoidPtrPtr]],

  // // Backup functions for ECDSA
  // MPCCRYPTO_API int MPCCrypto_initBackupEcdsaKey(int peer, MPCCryptoShare * share, const uint8_t* pub_backup_key, int pub_backup_key_size, MPCCryptoContext ** context);
  MPCCrypto_initBackupEcdsaKey: [ref.types.int, [ref.types.int, VoidPtr, Uint8Ptr, ref.types.int, VoidPtrPtr]],
  // MPCCRYPTO_API int MPCCrypto_getResultBackupEcdsaKey(MPCCryptoContext * context, uint8_t * out, int * out_size);
  MPCCrypto_getResultBackupEcdsaKey: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],
  // MPCCRYPTO_API int MPCCrypto_verifyEcdsaBackupKey(const uint8_t* pub_backup_key, int pub_backup_key_size, const uint8_t* pub_key, int pub_key_size, const uint8_t* backup, int backup_size);
  MPCCrypto_verifyEcdsaBackupKey: [ref.types.int, [Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int]],
  // MPCCRYPTO_API int MPCCrypto_restoreEcdsaKey(const uint8_t* prv_backup_key, int prv_backup_key_size, const uint8_t* pub_key, int pub_key_size, const uint8_t* backup, int backup_size, uint8_t * prv_key, int * prv_key_size);
  MPCCrypto_restoreEcdsaKey: [ref.types.int, [Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int, Uint8Ptr, ref.types.int, Uint8Ptr, IntPtr]],

  // Backup functions for EdDSA
  // MPCCRYPTO_API int MPCCrypto_initBackupEddsaKey(int peer, MPCCryptoShare * share, const uint8_t* pub_backup_key, int pub_backup_key_size, MPCCryptoContext ** context);
  MPCCrypto_initBackupEddsaKey: [ref.types.int, [ref.types.int, VoidPtr, Uint8Ptr, ref.types.int, VoidPtrPtr]],
  // MPCCRYPTO_API int MPCCrypto_getResultBackupEddsaKey(MPCCryptoContext * context, uint8_t * out, int * out_size);
  MPCCrypto_getResultBackupEddsaKey: [ref.types.int, [VoidPtr, Uint8Ptr, IntPtr]],
  // MPCCRYPTO_API int MPCCrypto_verifyEddsaBackupKey(const uint8_t* pub_backup_key, int pub_backup_key_size, const uint8_t* pub_key, const uint8_t* backup, int backup_size);
  MPCCrypto_verifyEddsaBackupKey: [ref.types.int, [Uint8Ptr, ref.types.int, Uint8Ptr, Uint8Ptr, ref.types.int]],
  // MPCCRYPTO_API int MPCCrypto_restoreEddsaKey(const uint8_t* prv_backup_key, int prv_backup_key_size, const uint8_t* pub_key, const uint8_t* backup, int backup_size, uint8_t * out);  // [pub_ley]=32, |out|=32
  MPCCrypto_restoreEddsaKey: [ref.types.int, [Uint8Ptr, ref.types.int, Uint8Ptr, Uint8Ptr, ref.types.int, Uint8Ptr]],


  // BIP32 functions
  // MPCCRYPTO_API int MPCCrypto_initDeriveBIP32(int peer, MPCCryptoShare * share, int hardened, unsigned index, MPCCryptoContext ** context);
  MPCCrypto_initDeriveBIP32: [ref.types.int, [ref.types.int, VoidPtr, ref.types.int, ref.types.uint, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_getResultDeriveBIP32(MPCCryptoContext * context, MPCCryptoShare ** new_share);
  MPCCrypto_getResultDeriveBIP32: [ref.types.int, [VoidPtr, VoidPtrPtr]],

  // MPCCRYPTO_API int MPCCrypto_getBIP32Info(MPCCryptoShare * share, bip32_info_t * bip32_info);
  // MPCCRYPTO_API int MPCCrypto_serializePubBIP32(MPCCryptoShare * share, char * out, int * out_size);
  MPCCrypto_serializePubBIP32: [ref.types.int, [VoidPtr, VoidPtr, IntPtr]],
});

mpc.checkAndThrowError = function checkAndThrowError(errorCode) {
  if (errorCode === 0) {
    return;
  }
  throw Error(`MPC error ${errorCode}`);
};

mpc.IntPtr = IntPtr;
mpc.Uint8Ptr = Uint8Ptr;
mpc.UintPtr = UintPtr;
mpc.VoidPtr = VoidPtr;
mpc.VoidPtrPtr = VoidPtrPtr;

mpc.flags = {
  FINISHED: 1,
  CHANGED: 2,
};

module.exports = mpc;
