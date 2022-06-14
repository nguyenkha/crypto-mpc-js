# Crypto Multi-party Computation
JavaScript wrapper for [Unbound C implementation](https://github.com/unbound-tech/blockchain-crypto-mpc)

```
npm install crypto-mpc
```

```
yarn add crypto-mpc
```

## WIP
I only provide MacOS Catalina 10.15 and Ubuntu 18.04 pre-built binaries. You can build another OS binary from Unbound source code.

## Mac M1 Support
Because the Original C implementation has Platform specific Code it is necessary to provide a different set of binaries for this project to work on the Apple M1 Chip.
If you need to run on M1, replace the `MPCCrypto.so` and `-dylib` with `MPCCrypto-m1.so` and `-dylib`.

TODO: Change native.js to load correct binaries depending of underlying hardware.

## Quick ECDSA Example
```
docker-compose up
```
