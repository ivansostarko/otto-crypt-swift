# OTTO Crypt — Swift Package (iOS/macOS)



Implements **OTTO-256-GCM-HKDF-SIV**:
- **AES-256-GCM** (CryptoKit) with 16-byte tags
- **HKDF(SHA-256)** key schedule and deterministic per-chunk nonces
- **Argon2id** (libsodium `crypto_pwhash` via `Clibsodium`)
- **X25519** (libsodium `crypto_scalarmult`)

## Install

Add to `Package.swift`:
```swift
.package(url: "https://github.com/ivansostarko/otto-crypt-swift.git", from: "0.1.0")
```

And depend on:
```swift
.product(name: "IvanSostarkoOttoCrypt", package: "otto-crypt-swift")
```

This package depends on **Swift-Sodium**, which bundles **libsodium** for iOS/macOS.

## Quick Start

```swift
import IvanSostarkoOttoCrypt

let otto = OttoCrypt()

// Strings
var opt = Options(); opt.password = "P@ssw0rd!"
let enc = try otto.encryptString(Data("Hello OTTO".utf8), options: opt)
let dec = try otto.decryptString(enc.cipherAndTag, header: enc.header, options: opt)
print(String(data: dec, encoding: .utf8)!) // "Hello OTTO"

// Files (photos/docs/audio/video)
try otto.encryptFile(inputPath: "/path/in.mp4", outputPath: "/path/in.mp4.otto", options: opt)
try otto.decryptFile(inputPath: "/path/in.mp4.otto", outputPath: "/path/in.dec.mp4", options: opt)

// X25519 E2E
let kp = KeyExchange.generateKeypair()
var encOpt = Options(); encOpt.recipientPublic = kp.publicKey.base64EncodedString()
var decOpt = Options(); decOpt.senderSecret = kp.secret.base64EncodedString()
try otto.encryptFile(inputPath: "photo.jpg", outputPath: "photo.jpg.otto", options: encOpt)
try otto.decryptFile(inputPath: "photo.jpg.otto", outputPath: "photo.dec.jpg", options: decOpt)
```

## Algorithm & Format (compatible with Laravel)

### Header
```
magic      : "OTTO1" (5 bytes)
algo_id    : 0xA1
kdf_id     : 0x01=password | 0x02=raw key | 0x03=X25519
flags      : bit0=chunked
reserved   : 0x00
header_len : uint16 BE of HVAR
HVAR:
  file_salt  (16)
  if kdf=01 (password): pw_salt(16) + opslimit(uint32 BE) + memlimitKiB(uint32 BE)
  if kdf=03 (X25519):   eph_pubkey(32)
```
**AEAD AD** = full header bytes.

### Chunk streaming
Per chunk: `[len (u32 BE of ciphertext)] [ciphertext] [tag(16)]`

### Key schedule
```
enc_key   = HKDF(master, 32, info="OTTO-ENC-KEY",  salt=file_salt)
nonce_key = HKDF(master, 32, info="OTTO-NONCE-KEY", salt=file_salt)
nonce_i   = HKDF(nonce_key, 12, info="OTTO-CHUNK-NONCE" || counter64be, salt="")
```

### Master key sources
- **Argon2id**: derive from password using libsodium `crypto_pwhash`. Header stores the exact `opslimit` and `memlimitKiB` used.
- **Raw 32-byte key**: pass via `Options.rawKey` (hex/base64/raw).
- **X25519**: sender generates ephemeral secret/public; header carries `eph_pubkey`. Both sides compute `shared = scalarmult(sk, pk)` → `master = HKDF(shared, ...)`.

## Security Notes

- AES-GCM provides confidentiality + integrity with 16-byte tags; header is bound as AD.
- Deterministic nonces prevent accidental GCM nonce reuse through HKDF-SIV style derivation.
- Prefer **E2E (X25519)** for messengers; if using passwords, enforce strong Argon2id parameters.
- Best-effort key erasure in Swift is limited by ARC/CoW; treat endpoints as sensitive.
- As a custom composition, obtain an **independent security review** before production.



MIT © 2025 Ivan Sostarko
