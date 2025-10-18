import Foundation
import Clibsodium

public struct Keypair {
    public let secret: Data
    public let publicKey: Data
}

public enum KeyExchange {
    public static func generateKeypair() -> Keypair {
        var sk = Data(count: Int(crypto_scalarmult_SCALARBYTES()))
        sk.withUnsafeMutableBytes { randombytes_buf($0.baseAddress, $0.count) }
        var pk = Data(count: Int(crypto_scalarmult_BYTES()))
        pk.withUnsafeMutableBytes { pkPtr in
            sk.withUnsafeBytes { skPtr in
                crypto_scalarmult_base(pkPtr.bindMemory(to: UInt8.self).baseAddress, skPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return Keypair(secret: sk, publicKey: pk)
    }
    
    public static func deriveShared(secret: Data, publicKey: Data) throws -> Data {
        guard secret.count == Int(crypto_scalarmult_SCALARBYTES()), publicKey.count == Int(crypto_scalarmult_BYTES()) else {
            throw OttoError.invalidKey("x25519 sizes")
        }
        var shared = Data(count: Int(crypto_scalarmult_BYTES()))
        let rc = shared.withUnsafeMutableBytes { shPtr -> Int32 in
            secret.withUnsafeBytes { skPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    crypto_scalarmult(shPtr.bindMemory(to: UInt8.self).baseAddress,
                                      skPtr.bindMemory(to: UInt8.self).baseAddress,
                                      pkPtr.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        if rc != 0 { throw OttoError.crypto("x25519 scalarmult failed") }
        return shared
    }
    
    public static func deriveSessionKey(shared: Data, salt: Data, context: String) -> Data {
        return HKDF.derive(ikm: shared, length: 32, info: Data(context.utf8), salt: salt)
    }
}
