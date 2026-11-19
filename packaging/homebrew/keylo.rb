# Homebrew cask for Keylo. Lives in the tap repository tulde23/homebrew-keylo as Casks/keylo.rb:
#   brew install --cask tulde23/keylo/keylo
# On a new release, update version and sha256 (the macos-arm64.zip line of SHA256SUMS.txt).
cask "keylo" do
  version "1.6.16"
  sha256 "163eeef60f07895bcf532d54126370c7d1585e7bba44297f076c1fdb109a4e02"

  url "https://github.com/tulde23/keylo/releases/download/v#{version}/keylo-#{version}-macos-arm64.zip"
  name "Keylo"
  desc "Secrets manager that lets AI agents use credentials without seeing them"
  homepage "https://github.com/tulde23/keylo"

  livecheck do
    url :url
    strategy :github_latest
  end

  auto_updates true
  depends_on arch: :arm64
  depends_on :macos

  app "Keylo.app"
  binary "#{appdir}/Keylo.app/Contents/MacOS/keylo"

  # Secrets themselves are in the login keychain (service "Keylo") and aren't removed.
  zap trash: [
    "~/Library/Application Support/Keylo",
    "~/Library/Caches/io.github.tulde23.keylo",
    "~/Library/Preferences/io.github.tulde23.keylo.plist",
    "~/Library/Saved Application State/io.github.tulde23.keylo.savedState",
    "~/Library/WebKit/io.github.tulde23.keylo",
  ]
end
