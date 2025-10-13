import XCTest
@testable import IvanSostarkoOttoCrypt

final class OttoCryptTests: XCTestCase {
    func testRoundTripPassword() throws {
        let o = OttoCrypt()
        var opt = Options()
        opt.password = "P@ssw0rd!"
        let enc = try o.encryptString(Data("hello".utf8), options: opt)
        let dec = try o.decryptString(enc.cipherAndTag, header: enc.header, options: opt)
        XCTAssertEqual(String(data: dec, encoding: .utf8), "hello")
    }
}
