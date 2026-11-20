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

// ---- Touch ID vault unlock: a 32-byte key sealed behind biometrics in the data-protection keychain.
// bio-store reads a base64 key on stdin; bio-get prompts Touch ID and prints it back; it never leaves
// the device (ThisDeviceOnly) and can't be read without the gesture.

let bioService = "io.github.tulde23.keylo.touchid"
let bioAccount = "vault-key"

func bioBase() -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: bioService,
     kSecAttrAccount as String: bioAccount,
     kSecUseDataProtectionKeychain as String: true]
}

/// Exit 0 if Touch ID (biometrics) can be used here, 2 otherwise.
func bioAvailable() -> Int32 {
    var error: NSError?
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) ? 0 : 2
}

/// Stores the base64 key from stdin behind biometrics. No prompt (writing doesn't authenticate).
func bioStore() -> Int32 {
    let b64 = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = Data(base64Encoded: b64), data.count == 32 else {
        FileHandle.standardError.write("expected a 32-byte base64 key on stdin\n".data(using: .utf8)!)
        return 3
    }
    SecItemDelete(bioBase() as CFDictionary)
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil) else {
        FileHandle.standardError.write("couldn't build the access control\n".data(using: .utf8)!)
        return 3
    }
    var add = bioBase()
    add[kSecAttrAccessControl as String] = access
    add[kSecValueData as String] = data
    let status = SecItemAdd(add as CFDictionary, nil)
    if status != errSecSuccess {
        FileHandle.standardError.write("SecItemAdd failed: \(status)\n".data(using: .utf8)!)
        return 3
    }
    return 0
}

/// Prompts Touch ID and prints the stored key as base64. Exit 1 cancelled, 2 not enrolled.
func bioGet(_ reason: String) -> Int32 {
    var query = bioBase()
    query[kSecReturnData as String] = true
    query[kSecUseOperationPrompt as String] = reason
    var out: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    switch status {
    case errSecSuccess:
        guard let data = out as? Data else { return 3 }
        FileHandle.standardOutput.write((data.base64EncodedString() + "\n").data(using: .utf8)!)
        return 0
    case errSecUserCanceled: return 1
    case errSecItemNotFound: return 2
    default:
        FileHandle.standardError.write("SecItemCopyMatching failed: \(status)\n".data(using: .utf8)!)
        return 3
    }
}

/// Removes the stored key.
func bioRemove() -> Int32 {
    let status = SecItemDelete(bioBase() as CFDictionary)
    return (status == errSecSuccess || status == errSecItemNotFound) ? 0 : 3
}

switch argument(1) {
case "auth": exit(authenticate(argument(2, "use your secrets")))
case "copy": exit(copy())
case "clear": exit(clear(argument(2)))
case "approve": exit(approve(title: argument(2, "Keylo"), message: argument(3), allowAlways: argument(4) == "1"))
case "bio-available": exit(bioAvailable())
case "bio-store": exit(bioStore())
case "bio-get": exit(bioGet(argument(2, "unlock your Keylo vault")))
case "bio-remove": exit(bioRemove())
default:
    FileHandle.standardError.write("usage: keylo-mac auth REASON | copy | clear COUNT | approve TITLE MESSAGE [1] | bio-available | bio-store | bio-get [REASON] | bio-remove\n".data(using: .utf8)!)
    exit(64)
}
