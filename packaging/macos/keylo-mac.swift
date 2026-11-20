// keylo-mac: the parts of Keylo on macOS that need Apple frameworks. Built by build.sh (swiftc).
//
//   keylo-mac auth REASON                 Touch ID / Apple Watch / password. Exit 0 verified, 1 canceled,
//                                         2 unavailable, 3 failed (message on stdout).
//   keylo-mac copy                        Copy stdin to the pasteboard, concealed and transient; prints
//                                         the pasteboard's change count.
//   keylo-mac clear COUNT                 Clear the pasteboard if its change count is still COUNT (exit 0).
//   keylo-mac approve TITLE MESSAGE [1]   Ask with an alert: Deny / Allow once (/ Always allow when 1).
//                                         Exit 10 deny, 11 once, 12 always.

import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

let args = CommandLine.arguments

func argument(_ index: Int, _ fallback: String = "") -> String {
    index < args.count ? args[index] : fallback
}

func authenticate(_ reason: String) -> Int32 {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        print(error?.localizedDescription ?? "unavailable")
        return 2
    }

    var code: Int32 = 3
    let done = DispatchSemaphore(value: 0)
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, failure in
        if success {
            code = 0
        } else if let laError = failure as? LAError,
                  [.userCancel, .appCancel, .systemCancel].contains(laError.code) {
            code = 1
        } else {
            print(failure?.localizedDescription ?? "failed")
            code = 3
        }
        done.signal()
    }
    done.wait()
    return code
}

let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

func copy() -> Int32 {
    let text = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
    let pasteboard = NSPasteboard.general
    pasteboard.declareTypes([.string, concealed, transient], owner: nil)
    pasteboard.setString(text, forType: .string)
    pasteboard.setString("", forType: concealed)
    pasteboard.setString("", forType: transient)
    print(pasteboard.changeCount)
    return 0
}

func clear(_ count: String) -> Int32 {
    let pasteboard = NSPasteboard.general
    guard let expected = Int(count), pasteboard.changeCount == expected else { return 1 }
    pasteboard.clearContents()
    return 0
}

func approve(title: String, message: String, allowAlways: Bool) -> Int32 {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)

    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title
    alert.informativeText = message
    alert.addButton(withTitle: "Deny")          // first button: the default (Return) is the safe choice
    alert.addButton(withTitle: "Allow once")
    if allowAlways { alert.addButton(withTitle: "Always allow") }
    alert.window.level = .floating

    switch alert.runModal() {
    case .alertSecondButtonReturn: return 11
    case .alertThirdButtonReturn: return 12
    default: return 10
    }
}

// ---- Touch ID vault unlock via the Secure Enclave. A P256 key lives in the Secure Enclave behind
// biometrics; ECDH against a fixed throwaway peer gives a stable 32-byte key that wraps the vault key.
// The key's blob is useless without this Mac's Secure Enclave and a Touch ID gesture, and it needs no
// keychain entitlement (a biometric keychain item would). Keylo stores the blob; bio-derive turns it
// back into the key.

let bioInfo = Data("keylo-touchid:v1".utf8)

/// A 32-byte key from the Secure Enclave shared secret, as base64.
func bioKey(_ shared: SharedSecret) -> String {
    let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: bioInfo, outputByteCount: 32)
    return key.withUnsafeBytes { Data($0).base64EncodedString() }
}

/// 1 if the user cancelled, 3 otherwise; writes the message.
func bioError(_ error: Error) -> Int32 {
    if let la = error as? LAError, [.userCancel, .appCancel, .systemCancel].contains(la.code) { return 1 }
    let message = "\(error)"
    if message.contains("-128") || message.lowercased().contains("cancel") { return 1 }
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    return 3
}

/// Exit 0 if the Secure Enclave and biometrics are usable here, 2 otherwise.
func bioAvailable() -> Int32 {
    guard SecureEnclave.isAvailable else { return 2 }
    var error: NSError?
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) ? 0 : 2
}

/// Creates the Secure Enclave key (prompts Touch ID) and prints two lines: the key blob Keylo stores,
/// then the 32-byte unlock key, both base64.
func bioEnroll() -> Int32 {
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil) else {
        FileHandle.standardError.write("couldn't build the access control\n".data(using: .utf8)!)
        return 3
    }
    do {
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let peer = P256.KeyAgreement.PrivateKey() // throwaway; only its public half is kept, in the blob
        let shared = try enclave.sharedSecretFromKeyAgreement(with: peer.publicKey)
        let blob = enclave.dataRepresentation.base64EncodedString() + "." + peer.publicKey.rawRepresentation.base64EncodedString()
        FileHandle.standardOutput.write((blob + "\n" + bioKey(shared) + "\n").data(using: .utf8)!)
        return 0
    } catch {
        return bioError(error)
    }
}

/// Re-derives the 32-byte unlock key from the stored blob (prompts Touch ID). Prints it base64.
func bioDerive(_ blob: String) -> Int32 {
    let parts = blob.split(separator: ".")
    guard parts.count == 2,
          let enclaveData = Data(base64Encoded: String(parts[0])),
          let peerData = Data(base64Encoded: String(parts[1])) else {
        FileHandle.standardError.write("unreadable Touch ID blob\n".data(using: .utf8)!)
        return 3
    }
    do {
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: enclaveData)
        let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerData)
        let shared = try enclave.sharedSecretFromKeyAgreement(with: peer)
        FileHandle.standardOutput.write((bioKey(shared) + "\n").data(using: .utf8)!)
        return 0
    } catch {
        return bioError(error)
    }
}

switch argument(1) {
case "auth": exit(authenticate(argument(2, "use your secrets")))
case "copy": exit(copy())
case "clear": exit(clear(argument(2)))
case "approve": exit(approve(title: argument(2, "Keylo"), message: argument(3), allowAlways: argument(4) == "1"))
case "bio-available": exit(bioAvailable())
case "bio-enroll": exit(bioEnroll())
case "bio-derive": exit(bioDerive(argument(2)))
default:
    FileHandle.standardError.write("usage: keylo-mac auth REASON | copy | clear COUNT | approve TITLE MESSAGE [1] | bio-available | bio-enroll | bio-derive BLOB\n".data(using: .utf8)!)
    exit(64)
}
