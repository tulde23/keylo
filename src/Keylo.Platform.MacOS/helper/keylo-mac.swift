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

switch argument(1) {
case "auth": exit(authenticate(argument(2, "use your secrets")))
case "copy": exit(copy())
case "clear": exit(clear(argument(2)))
case "approve": exit(approve(title: argument(2, "Keylo"), message: argument(3), allowAlways: argument(4) == "1"))
default:
    FileHandle.standardError.write("usage: keylo-mac auth REASON | copy | clear COUNT | approve TITLE MESSAGE [1]\n".data(using: .utf8)!)
    exit(64)
}
