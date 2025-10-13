import Foundation
import CryptoKit

enum HKDF {
    static func derive(ikm: Data, length: Int, info: Data, salt: Data) -> Data {
        // HKDF-Extract with HMAC-SHA256
        let prk: Data = {
            let key = SymmetricKey(data: salt.isEmpty ? Data(repeating: 0, count: 32) : salt)
            let mac = HMAC<SHA256>.authenticationCode(for: ikm, using: key)
            return Data(mac)
        }()
        // HKDF-Expand
        let hashLen = 32
        let n = Int(ceil(Double(length)/Double(hashLen)))
        var t = Data()
        var okm = Data(capacity: n * hashLen)
        for i in 1...n {
            var h = HMAC<SHA256>(key: SymmetricKey(data: prk))
            h.update(data: t)
            h.update(data: info)
            h.update(data: Data([UInt8(i)]))
            let mac = Data(h.finalize())
            okm.append(mac)
            t = mac
        }
        return okm.prefix(length)
    }
}
