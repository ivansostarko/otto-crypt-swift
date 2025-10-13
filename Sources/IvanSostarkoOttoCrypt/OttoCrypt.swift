import Foundation
import CryptoKit
import Clibsodium

public enum KDF: UInt8 {
    case password = 0x01
    case rawKey   = 0x02
    case x25519   = 0x03
}

public struct Options {
    public var password: String? = nil
    public var recipientPublic: String? = nil
    public var senderSecret: String? = nil
    public var rawKey: String? = nil
    public var opslimit: UInt32? = nil
    public var memlimit: UInt64? = nil // bytes
    
    public init() {}
}

public struct EncResult {
    public let cipherAndTag: Data
    public let header: Data
}

public final class OttoCrypt {
    public static let MAGIC = Data("OTTO1".utf8)
    public static let ALGO_ID: UInt8 = 0xA1
    public static let FLAG_CHUNKED: UInt8 = 0x01
    
    private let chunkSize: Int
    
    public init(chunkSize: Int = 1<<20) {
        self.chunkSize = chunkSize
    }
    
    // MARK: - Public API
    
    public func encryptString(_ plaintext: Data, options opt: Options) throws -> EncResult {
        let ctx = try initContext(opt: opt, chunked: false)
        let nonce = chunkNonce(nonceKey: ctx.nonceKey, counter: 0)
        let (cipher, tag) = try aesGcmEncrypt(plain: plaintext, key32: ctx.encKey, nonce12: nonce, aad: ctx.header)
        var out = cipher
        out.append(tag)
        return EncResult(cipherAndTag: out, header: ctx.header)
    }
    
    public func decryptString(_ cipherAndTag: Data, header: Data, options opt: Options) throws -> Data {
        guard cipherAndTag.count >= 16 else { throw OttoError.crypto("cipher too short") }
        let ctx = try initContextForDecrypt(header: header, opt: opt)
        let cipher = cipherAndTag.dropLast(16)
        let tag = cipherAndTag.suffix(16)
        let nonce = chunkNonce(nonceKey: ctx.nonceKey, counter: 0)
        return try aesGcmDecrypt(cipher: cipher, tag: tag, key32: ctx.encKey, nonce12: nonce, aad: ctx.aad)
    }
    
    public func encryptFile(inputPath: String, outputPath: String, options opt: Options) throws {
        let ctx = try initContext(opt: opt, chunked: true)
        FileManager.default.createFile(atPath: outputPath, contents: nil, attributes: nil)
        let outH = try FileHandle(forWritingTo: URL(fileURLWithPath: outputPath))
        defer { try? outH.close() }
        try outH.write(contentsOf: ctx.header)
        
        let inH = try FileHandle(forReadingFrom: URL(fileURLWithPath: inputPath))
        defer { try? inH.close() }
        
        var counter: UInt64 = 0
        while true {
            let chunk = try inH.read(upToCount: chunkSize) ?? Data()
            if chunk.isEmpty { break }
            let nonce = chunkNonce(nonceKey: ctx.nonceKey, counter: counter)
            let (c, tag) = try aesGcmEncrypt(plain: chunk, key32: ctx.encKey, nonce12: nonce, aad: ctx.aad)
            var lenBE = Data()
            lenBE.appendBE32(UInt32(c.count))
            try outH.write(contentsOf: lenBE)
            try outH.write(contentsOf: c)
            try outH.write(contentsOf: tag)
            counter &+= 1
        }
    }
    
    public func decryptFile(inputPath: String, outputPath: String, options opt: Options) throws {
        let inH = try FileHandle(forReadingFrom: URL(fileURLWithPath: inputPath))
        defer { try? inH.close() }
        let header = try readHeader(from: inH)
        let ctx = try initContextForDecrypt(header: header, opt: opt)
        FileManager.default.createFile(atPath: outputPath, contents: nil, attributes: nil)
        let outH = try FileHandle(forWritingTo: URL(fileURLWithPath: outputPath))
        defer { try? outH.close() }
        
        var counter: UInt64 = 0
        while true {
            guard let lenBytes = try inH.read(upToCount: 4), lenBytes.count == 4 else { break }
            let clen = be32(lenBytes, 0)
            if clen == 0 { break }
            guard let c = try inH.read(upToCount: Int(clen)), c.count == Int(clen) else {
                throw OttoError.io("truncated cipher")
            }
            guard let tag = try inH.read(upToCount: 16), tag.count == 16 else {
                throw OttoError.io("missing tag")
            }
            let nonce = chunkNonce(nonceKey: ctx.nonceKey, counter: counter)
            let p = try aesGcmDecrypt(cipher: c, tag: tag, key32: ctx.encKey, nonce12: nonce, aad: ctx.aad)
            try outH.write(contentsOf: p)
            counter &+= 1
        }
    }
    
    // MARK: - Internals
    
    private struct Ctx {
        let header: Data
        let aad: Data
        let encKey: Data
        let nonceKey: Data
        let master: Data
    }
    
    private func initContext(opt: Options, chunked: Bool) throws -> Ctx {
        let fileSalt = randomBytes(16)
        var header = Data()
        header.append(Self.MAGIC)
        header.append(Self.ALGO_ID)
        
        var kdfId: KDF
        var headerExtra = Data()
        var master = Data(count: 32)
        
        if let pw = opt.password, !pw.isEmpty {
            kdfId = .password
            let pwSalt = randomBytes(16)
            let ops = opt.opslimit ?? UInt32(crypto_pwhash_opslimit_mod())
            let mem = opt.memlimit ?? UInt64(crypto_pwhash_memlimit_mod())
            // Argon2id derive 32-byte master
            let rc = master.withUnsafeMutableBytes { outPtr -> Int32 in
                pwSalt.withUnsafeBytes { saltPtr in
                    (pw as NSString).utf8String!.withMemoryRebound(to: CChar.self, capacity: pw.count) { pwCStr in
                        crypto_pwhash(outPtr.bindMemory(to: UInt8.self).baseAddress,
                                      UInt64(master.count),
                                      pwCStr,
                                      UInt64(pw.utf8.count),
                                      saltPtr.bindMemory(to: UInt8.self).baseAddress,
                                      UInt64(ops),
                                      mem,
                                      Int32(crypto_pwhash_ALG_ARGON2ID13()))
                    }
                }
            }
            if rc != 0 { throw OttoError.crypto("crypto_pwhash failed") }
            headerExtra.append(pwSalt)
            headerExtra.appendBE32(ops)
            headerExtra.appendBE32(UInt32(mem / 1024))
            header.append(kdfId.rawValue)
        } else if let raw = opt.rawKey, !raw.isEmpty {
            kdfId = .rawKey
            let rk = decodeKey(raw)
            guard rk.count == 32 else { throw OttoError.invalidKey("rawKey must be 32 bytes") }
            master = rk
            header.append(kdfId.rawValue)
        } else if let rcpt = opt.recipientPublic, !rcpt.isEmpty {
            kdfId = .x25519
            let rcptBytes = decodeKey(rcpt)
            guard rcptBytes.count == Int(crypto_scalarmult_BYTES()) else { throw OttoError.invalidKey("recipientPublic length") }
            var ephSk = Data(count: Int(crypto_scalarmult_SCALARBYTES()))
            ephSk.withUnsafeMutableBytes { randombytes_buf($0.baseAddress, $0.count) }
            var ephPk = Data(count: Int(crypto_scalarmult_BYTES()))
            ephPk.withUnsafeMutableBytes { pkPtr in
                ephSk.withUnsafeBytes { skPtr in
                    crypto_scalarmult_base(pkPtr.bindMemory(to: UInt8.self).baseAddress, skPtr.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            var shared = Data(count: Int(crypto_scalarmult_BYTES()))
            let rc = shared.withUnsafeMutableBytes { shPtr -> Int32 in
                ephSk.withUnsafeBytes { skPtr in
                    rcptBytes.withUnsafeBytes { pkPtr in
                        crypto_scalarmult(shPtr.bindMemory(to: UInt8.self).baseAddress,
                                          skPtr.bindMemory(to: UInt8.self).baseAddress,
                                          pkPtr.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
            }
            if rc != 0 { throw OttoError.crypto("x25519 scalarmult failed") }
            master = HKDF.derive(ikm: shared, length: 32, info: Data("OTTO-E2E-MASTER".utf8), salt: fileSalt)
            headerExtra.append(ephPk)
            header.append(kdfId.rawValue)
        } else {
            throw OttoError.invalidKey("Provide one of: password, rawKey, recipientPublic")
        }
        
        header.append(chunked ? Self.FLAG_CHUNKED : 0x00)
        header.append(0x00) // reserved
        
        var varPart = Data()
        varPart.append(fileSalt)
        varPart.append(headerExtra)
        
        header.appendBE16(UInt16(varPart.count))
        header.append(varPart)
        
        let encKey = HKDF.derive(ikm: master, length: 32, info: Data("OTTO-ENC-KEY".utf8), salt: fileSalt)
        let nonceKey = HKDF.derive(ikm: master, length: 32, info: Data("OTTO-NONCE-KEY".utf8), salt: fileSalt)
        
        return Ctx(header: header, aad: header, encKey: encKey, nonceKey: nonceKey, master: master)
    }
    
    private func initContextForDecrypt(header: Data, opt: Options) throws -> Ctx {
        guard header.count >= 11 else { throw OttoError.invalidHeader("too short") }
        guard header.prefix(5) == Self.MAGIC else { throw OttoError.invalidHeader("magic") }
        guard header[5] == Self.ALGO_ID else { throw OttoError.invalidHeader("algo") }
        let kdfId = header[6]
        // header[7] flags; header[8] reserved
        let hlen = UInt16(bigEndian: header.subdata(in: 9..<11).withUnsafeBytes { $0.load(as: UInt16.self) })
        guard header.count >= 11 + Int(hlen) else { throw OttoError.invalidHeader("truncated") }
        let varPart = header.subdata(in: 11..<(11+Int(hlen)))
        var off = 0
        let fileSalt = varPart.subdata(in: off..<(off+16)); off += 16
        
        var master = Data(count: 32)
        if kdfId == KDF.password.rawValue {
            let pwSalt = varPart.subdata(in: off..<(off+16)); off += 16
            let ops = be32(varPart, off); off += 4
            let memKiB = be32(varPart, off); off += 4
            guard let pw = opt.password, !pw.isEmpty else { throw OttoError.invalidKey("password required") }
            let memBytes = UInt64(memKiB) * 1024
            let rc = master.withUnsafeMutableBytes { outPtr -> Int32 in
                pwSalt.withUnsafeBytes { saltPtr in
                    (pw as NSString).utf8String!.withMemoryRebound(to: CChar.self, capacity: pw.count) { pwCStr in
                        crypto_pwhash(outPtr.bindMemory(to: UInt8.self).baseAddress,
                                      UInt64(master.count),
                                      pwCStr,
                                      UInt64(pw.utf8.count),
                                      saltPtr.bindMemory(to: UInt8.self).baseAddress,
                                      UInt64(ops),
                                      memBytes,
                                      Int32(crypto_pwhash_ALG_ARGON2ID13()))
                    }
                }
            }
            if rc != 0 { throw OttoError.crypto("crypto_pwhash failed") }
        } else if kdfId == KDF.rawKey.rawValue {
            let rk = decodeKey(opt.rawKey)
            guard rk.count == 32 else { throw OttoError.invalidKey("rawKey (32 bytes)") }
            master = rk
        } else if kdfId == KDF.x25519.rawValue {
            let ephPk = varPart.subdata(in: off..<(off+Int(crypto_scalarmult_BYTES()))); off += Int(crypto_scalarmult_BYTES())
            let sk = decodeKey(opt.senderSecret)
            guard sk.count == Int(crypto_scalarmult_SCALARBYTES()) else { throw OttoError.invalidKey("senderSecret length") }
            var shared = Data(count: Int(crypto_scalarmult_BYTES()))
            let rc = shared.withUnsafeMutableBytes { shPtr -> Int32 in
                sk.withUnsafeBytes { skPtr in
                    ephPk.withUnsafeBytes { pkPtr in
                        crypto_scalarmult(shPtr.bindMemory(to: UInt8.self).baseAddress,
                                          skPtr.bindMemory(to: UInt8.self).baseAddress,
                                          pkPtr.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
            }
            if rc != 0 { throw OttoError.crypto("x25519 scalarmult failed") }
            master = HKDF.derive(ikm: shared, length: 32, info: Data("OTTO-E2E-MASTER".utf8), salt: fileSalt)
        } else {
            throw OttoError.invalidHeader("unknown kdf")
        }
        
        let encKey = HKDF.derive(ikm: master, length: 32, info: Data("OTTO-ENC-KEY".utf8), salt: fileSalt)
        let nonceKey = HKDF.derive(ikm: master, length: 32, info: Data("OTTO-NONCE-KEY".utf8), salt: fileSalt)
        let fullHeader = header.prefix(11+Int(hlen))
        return Ctx(header: fullHeader, aad: fullHeader, encKey: encKey, nonceKey: nonceKey, master: master)
    }
    
    private func chunkNonce(nonceKey: Data, counter: UInt64) -> Data {
        var ctrBE = counter.bigEndian
        var info = Data("OTTO-CHUNK-NONCE".utf8)
        withUnsafeBytes(of: &ctrBE) { info.append($0.bindMemory(to: UInt8.self)) }
        return HKDF.derive(ikm: nonceKey, length: 12, info: info, salt: Data())
    }
    
    private func aesGcmEncrypt(plain: Data, key32: Data, nonce12: Data, aad: Data) throws -> (Data, Data) {
        let key = SymmetricKey(data: key32)
        let nonce = try AES.GCM.Nonce(data: nonce12)
        let sealed = try AES.GCM.seal(plain, using: key, nonce: nonce, authenticating: aad)
        return (sealed.ciphertext, sealed.tag)
    }
    
    private func aesGcmDecrypt(cipher: Data, tag: Data, key32: Data, nonce12: Data, aad: Data) throws -> Data {
        let key = SymmetricKey(data: key32)
        let nonce = try AES.GCM.Nonce(data: nonce12)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipher, tag: tag)
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }
    
    private func readHeader(from h: FileHandle) throws -> Data {
        guard let fixed = try h.read(upToCount: 11), fixed.count == 11 else {
            throw OttoError.invalidHeader("bad fixed part")
        }
        guard fixed.prefix(5) == Self.MAGIC else { throw OttoError.invalidHeader("magic") }
        guard fixed[5] == Self.ALGO_ID else { throw OttoError.invalidHeader("algo") }
        let hlen = UInt16(bigEndian: fixed.subdata(in: 9..<11).withUnsafeBytes { $0.load(as: UInt16.self) })
        guard let varPart = try h.read(upToCount: Int(hlen)), varPart.count == Int(hlen) else {
            throw OttoError.invalidHeader("truncated var part")
        }
        var header = Data()
        header.append(fixed)
        header.append(varPart)
        return header
    }
}

// Helpers to fetch libsodium constants (work around C macro exposure)
private func crypto_pwhash_opslimit_mod() -> UInt64 { return UInt64(crypto_pwhash_opslimit_moderate()) }
private func crypto_pwhash_memlimit_mod() -> UInt64 { return UInt64(crypto_pwhash_memlimit_moderate()) }
