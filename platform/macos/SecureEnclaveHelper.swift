// Native key backend. Build and sign on macOS; NOT validated on a Mac in the
// cloud evidence bundle. Security.framework / OS UI / code signing are TCB.
import AppKit
import Foundation
import Security

struct Request: Decodable { let usage: String; let operation: String; let key_id: String; let data: String; let context: String }
struct Response: Encodable { let value: String }
enum Failure: Error { case rejected(String) }
func decode(_ s: String) throws -> Data {
    let b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    guard let data = Data(base64Encoded: b + String(repeating: "=", count: (4 - b.count % 4) % 4)) else { throw Failure.rejected("base64") }
    return data
}
func encode(_ d: Data) -> String { d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
func approve(_ request: Request, _ data: Data) throws {
    NSApplication.shared.setActivationPolicy(.accessory)
    let alert = NSAlert()
    alert.messageText = "Vault: \(request.operation) — \(request.key_id)"
    let details = request.operation == "sign" ? (String(data: data, encoding: .utf8) ?? "Non-text signing request") : request.context
    guard details.count <= 16384 else { throw Failure.rejected("request too large") }
    alert.informativeText = "Approve only the expected Vault operation.\n\n" + details
    alert.addButton(withTitle: "Deny"); alert.addButton(withTitle: "Approve")
    NSApplication.shared.activate(ignoringOtherApps: true)
    guard alert.runModal() == .alertSecondButtonReturn else { throw Failure.rejected("denied") }
}
func key(_ id: String, usage: String, create: Bool) throws -> SecKey {
    let tag = Data(("org.vault-rs.native." + usage + "." + id).utf8)
    var error: Unmanaged<CFError>?
    if create {
        let flags: SecAccessControlCreateFlags = usage == "interactive" ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else { throw Failure.rejected("access control") }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag, kSecAttrAccessControl as String: control]
        ]
        // No software fallback if Secure Enclave is unavailable.
        guard let k = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { throw Failure.rejected("Secure Enclave key creation failed") }
        return k
    }
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecUseDataProtectionKeychain as String: true, kSecReturnRef as String: true]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let result = result else { throw Failure.rejected("key unavailable") }
    let k = result as! SecKey
    let attributes = SecKeyCopyAttributes(k) as? [String: Any]
    guard (attributes?[kSecAttrTokenID as String] as? String) == (kSecAttrTokenIDSecureEnclave as String) else { throw Failure.rejected("non-hardware key rejected") }
    return k
}
do {
    // The root broker enters this dedicated account's GUI bootstrap namespace.
    // Data Protection Keychain and userPresence require that logged-in identity;
    // running this UI in a root launch daemon is not supported. Keychain items
    // are per-user; the AI account cannot open the registered owner's keys.
    guard getuid() >= 501, geteuid() == getuid() else { throw Failure.rejected("dedicated GUI key owner required") }
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count <= 65536 else { throw Failure.rejected("input too large") }
    let request = try JSONDecoder().decode(Request.self, from: input)
    guard ["interactive", "service"].contains(request.usage), !request.key_id.isEmpty, request.key_id.count <= 128,
          request.key_id.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 95 }),
          ["create", "public", "sign", "ecdh"].contains(request.operation) else { throw Failure.rejected("invalid operation") }
    let data = try decode(request.data)
    if request.operation == "create" || (request.usage == "interactive" && request.operation != "public") { try approve(request, data) }
    let k = try key(request.key_id, usage: request.usage, create: request.operation == "create")
    var error: Unmanaged<CFError>?
    let output: Data
    switch request.operation {
    case "create", "public":
        guard let pub = SecKeyCopyPublicKey(k), let bytes = SecKeyCopyExternalRepresentation(pub, &error) else { throw Failure.rejected("public key") }
        output = bytes as Data
    case "sign":
        guard let bytes = SecKeyCreateSignature(k, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) else { throw Failure.rejected("signature denied") }
        output = bytes as Data
    case "ecdh":
        guard data.count == 65, data.first == 4,
            let peer = SecKeyCreateWithData(data as CFData, [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: 256] as CFDictionary, &error),
            let bytes = SecKeyCopyKeyExchangeResult(k, .ecdhKeyExchangeStandard, peer, [SecKeyKeyExchangeParameter.requestedSize: 32] as CFDictionary, &error) else { throw Failure.rejected("ECDH denied") }
        output = bytes as Data
        guard output.count == 32 else { throw Failure.rejected("ECDH size") }
    default: throw Failure.rejected("unsupported")
    }
    FileHandle.standardOutput.write(try JSONEncoder().encode(Response(value: encode(output))))
} catch {
    FileHandle.standardError.write(Data("Native Vault key operation denied.\n".utf8))
    exit(1)
}
