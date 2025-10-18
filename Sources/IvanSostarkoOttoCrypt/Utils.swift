import Foundation

enum OttoError: Error, LocalizedError {
    case invalidHeader(String)
    case crypto(String)
    case invalidKey(String)
    case io(String)
    
    var errorDescription: String? {
        switch self {
        case .invalidHeader(let m): return "Header error: \(m)"
        case .crypto(let m): return "Crypto error: \(m)"
        case .invalidKey(let m): return "Key error: \(m)"
        case .io(let m): return "I/O error: \(m)"
        }
    }
}

extension Data {
    mutating func appendBE16(_ v: UInt16) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { append($0.bindMemory(to: UInt8.self)) }
    }
    mutating func appendBE32(_ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { append($0.bindMemory(to: UInt8.self)) }
    }
    static func fromHex(_ s: String) -> Data? {
        let len = s.count
        if len % 2 != 0 { return nil }
        var out = Data(capacity: len/2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            let byteStr = String(s[idx..<next])
            guard let b = UInt8(byteStr, radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        return out
    }
}

func decodeKey(_ s: String?) -> Data {
    guard let s = s?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return Data() }
    if s.range(of: "^[0-9a-fA-F]+$", options: .regularExpression) != nil, s.count % 2 == 0 {
        if let d = Data.fromHex(s) { return d }
    }
    if let d = Data(base64Encoded: s) { return d }
    return Data(s.utf8)
}

func be32(_ d: Data, _ off: Int) -> UInt32 {
    let sub = d.subdata(in: off..<(off+4))
    return sub.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
}

func randomBytes(_ count: Int) -> Data {
    var data = Data(count: count)
    let rc = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    precondition(rc == errSecSuccess, "SecRandomCopyBytes failed")
    return data
}
