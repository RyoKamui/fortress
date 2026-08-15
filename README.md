# Fortress

Fortress is a desktop app for creating and recovering encrypted BIP-39 seed backups.

It can generate a mnemonic, encrypt backup JSON with `age`, split recovery material with SSKR, open existing encrypted backups, recover SSKR shares, and derive public wallet addresses for Bitcoin, Ethereum, XRP, and Solana. It is not a wallet and does not keep a persistent secret store.

## Platform Architecture

- macOS uses a native SwiftUI/AppKit interface with standard macOS controls, menus, dialogs, accessibility behavior, appearance adaptation, and window management.
- Windows and Linux continue to use the shared Rust/egui interface.
- BIP-39, SSKR, backup serialization, age execution, validation, and address derivation remain a single Rust implementation on every platform.
- The native Mac interface talks to the bundled `fortress-core` helper over a private, long-lived, newline-delimited JSON channel. Sensitive request values are written to stdin, never command-line arguments or environment variables. Parsed request and response trees are explicitly zeroized by Rust after each operation.
- The bridge never returns derived private keys. It returns only the recovery material explicitly requested by the UI and public address results.

The Swift source is in `macos-native/FortressNative`. The Rust helper is the same `fortress` binary used by the egui application, started with the private `--native-bridge` mode inside the macOS bundle. This keeps one security implementation while allowing each platform to have an appropriate presentation layer.

## Build

Use the guided build script:

```sh
scripts/build-release.sh
```

On macOS, the menu is intentionally short:

```text
1) macOS app
2) Checks
q) Quit
```

Direct commands:

```sh
scripts/build-release.sh macos
scripts/build-release.sh linux
scripts/build-release.sh windows
scripts/build-release.sh check
```

Platform outputs:

- macOS: `target/release/Fortress.app` and `target/release/fortress-macos.zip`
- Linux: `target/release/Fortress.AppDir` and `target/release/fortress-linux.tar.gz`
- Windows: `target\release\Fortress Windows` and `target\release\fortress-windows.zip`

The macOS zip is only for release/upload/sharing. For local use, open the app bundle directly:

```sh
open "target/release/Fortress.app"
```

Run the egui frontend from source during development:

```sh
cargo run --locked
```

Use `scripts/build-release.sh macos` to compile and launch-test the actual native SwiftUI bundle. A normal Mac release contains:

```text
Fortress.app/Contents/MacOS/Fortress       native SwiftUI executable
Fortress.app/Contents/MacOS/fortress-core protected Rust bridge
Fortress.app/Contents/MacOS/age            bundled encryption tool
Fortress.app/Contents/MacOS/age-keygen     bundled identity tool
```

Release builds are guarded against embedding local filesystem paths such as user home directories. Use the build script, or call Cargo through the sanitized wrapper:

```sh
scripts/cargo-sanitized.sh build --release --locked
scripts/check-binary-paths.sh target/release/fortress
```

Raw `cargo build --release` without path-remap rustflags is blocked unless `FORTRESS_ALLOW_UNSANITIZED_RELEASE=1` is set.

## Release Builds

GitHub Actions builds native artifacts on each OS:

- `fortress-macos-aarch64` and `fortress-macos-x86_64`: Apple Silicon and Intel macOS app bundle zips
- `fortress-linux-aarch64` and `fortress-linux-x86_64`: ARM64 and x86-64 Linux AppDir tarballs
- `fortress-windows-x86_64`: x86-64 Windows GUI package zip
- raw egui binaries for Linux and Windows, and raw Rust core binaries for macOS, are also uploaded for debugging

macOS CI supports Developer ID signing and notarization when the repository provides `APPLE_CERTIFICATE_P12`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_DEVELOPER_ID_APPLICATION`, `APPLE_NOTARY_ID`, `APPLE_NOTARY_PASSWORD`, and `APPLE_TEAM_ID` secrets. Without them, development artifacts are ad-hoc signed and are not suitable for public Gatekeeper distribution.

Windows release builds use the Windows GUI subsystem, so double-clicking `fortress.exe` should open the GUI without a console window.

## Requirements

- Rust stable.
- macOS native builds require Xcode command-line tools with `swiftc` and the macOS SDK. Linux and Windows builds do not require Swift.
- Every packaged macOS, Linux, and Windows app includes pinned, checksum-verified `age` and `age-keygen` executables plus the age BSD-3-Clause license. `AGE_VERSION` is the single source of truth for the bundled version.
- The release workflow checks the official `age` release every Monday. When a newer version appears, it records the version and GitHub-published SHA-256 digests, commits the new pin, and rebuilds every supported package. If an existing release's published digest changes, automation stops instead of silently accepting the replacement.
- On every startup, a background task checks the official age GitHub release with network timeouts. A newer platform archive is downloaded into the per-user data directory, checked against GitHub's release-asset SHA-256 digest, launch-tested, and then preferred over the bundled offline fallback. Before every use, the cached executable is re-hashed against the authenticated archive; arbitrary version-named files in the cache are never selected. The signed app package itself is not modified.
- Automatic-update failures are visible in the sidebar; the bundled executable remains available offline.
- Running a raw standalone binary still falls back to an `age` command on `PATH` if neither an updated nor adjacent bundled executable exists.
- Optional: set `FORTRESS_AGE_BINARY=/absolute/path/to/age` to override the bundled or PATH-resolved executable with a specific trusted `age` binary.

Backups are encrypted by the bundled or installed `age` binary. The app accepts pasted public recipients directly, including `age1...`, `age1pq...` when supported by the selected `age` build, and supported SSH recipients. It also accepts a file containing public recipients, such as an age identity file with a `# public key:` comment.

To create a post-quantum hybrid recipient with an `age` build that supports it:

```sh
age-keygen -pq -o pq-key.txt
```

## Main Flows

The app opens at 1320 × 900 pixels. The native Mac interface remains usable down to 1080 × 740, follows the system light/dark appearance, and uses native scrolling and persistent scrollbars where configured by macOS. The egui Windows/Linux interface remains usable down to 1040 × 720 and uses a localized “More below” strip for long forms. Interface text and the full safety guide are available in English, Simplified Chinese, Japanese, and Korean.

Windows and Linux use Vulf Sans Regular/Bold with Noto Sans CJK fallback. macOS deliberately uses Apple’s native system typography so Dynamic Type sizing, CJK fallback, accessibility settings, and platform rendering behave like other Mac applications. Both interfaces share the fortress mark, graphite navigation, neutral surfaces, and a restrained indigo accent.

### Create Backup

- Generate a new 24-word BIP-39 mnemonic using OS randomness, optionally supplemented with an interactive full-screen mouse-movement ceremony, or import an existing valid BIP-39 seed phrase. The optional ceremony requires at least 30 seconds, 1,000 accepted pointer samples, 12 screen-diagonals of travel, 36 of 48 screen regions, 80 substantial direction changes, and three speed ranges.
- Review the mnemonic in compact numbered cells with inline word-list and checksum validation.
- Choose the BIP-39 language before generation.
- Enter an optional BIP-39 passphrase and choose whether to include it in the encrypted backup.
- Confirm non-empty passphrases to catch typing errors. BIP-39 itself cannot determine whether a passphrase belongs to a particular wallet because every passphrase produces a valid but different wallet.
- Save an age-encrypted backup by pasting a public recipient or selecting a recipient file.
- Confirm that the matching private identity is under your control, or create a new local identity with the packaged `age-keygen`; the matching public recipient is filled automatically.
- Enable SSKR to save recovery shares instead of the raw seed phrase.
- Choose SSKR group count, group threshold, shares per group, and required shares per group.
- Optionally export one private share per file as an atomically published recovery set. Distribute those files to separate trusted locations; keeping the complete set together does not provide loss redundancy.

### Open Backup

- Select an encrypted `.age` backup.
- Paste a literal `AGE-SECRET-KEY-...` identity or select an identity file.
- View the decrypted JSON in a structured, human-readable layout.
- Review direct or SSKR-recovered mnemonics in numbered word cells matching the Create Backup flow.
- Sensitive fields are masked until explicitly revealed.
- Unknown JSON fields are treated as sensitive and masked by default.
- SSKR backups are recovered automatically after decryption; the reconstructed phrase appears in the summary when sensitive values are revealed.
- Decrypted mnemonic and SSKR backups are loaded into address derivation automatically.
- Direct mnemonic backups are revalidated for wordlist and checksum before they are accepted. Backups with missing or unsupported language metadata are rejected rather than silently treated as English.

### Recover SSKR

- Paste one SSKR share per line.
- Shares can be raw hex or the share mnemonic format generated by this app.
- Select the BIP-39 language used for the share mnemonics.
- Recovered seeds are loaded into address derivation without writing plaintext to disk.

### Address Derivation

- Derive public addresses and public keys from a loaded or pasted mnemonic.
- Supported address types:
  - Bitcoin native SegWit: `m/84'/0'/0'/0/i`
  - Ethereum/EVM: `m/44'/60'/0'/0/i`
  - XRP: `m/44'/144'/0'/0/i`
  - Solana: `m/44'/501'/i'/0'`
- Bitcoin and Ethereum can optionally harden the final index.
- The table displays public data only.

### Help & Safety Guide

- Explains what Fortress does—and why it is not a wallet—in beginner-friendly language.
- Distinguishes a BIP-39 mnemonic from its optional passphrase and explains why only a known address can verify the intended wallet.
- Explains age public recipients, private identities, separation of materials, and the consequences of losing either side.
- Provides a concrete 2-of-3 SSKR group example, including per-group share thresholds and why separate export matters.
- Walks through a complete first-backup and recovery-drill workflow before real funds are deposited.
- Gives storage guidance, failure scenarios, and an end-to-end verification checklist.
- Includes complete English, Simplified Chinese, Japanese, and Korean versions that follow the selected interface language.

## Backup Format

New backups are JSON encrypted with age recipient encryption. They include schema metadata:

- `schema_version`
- `backup_type`
- `created_at_unix`
- `tool_version`
- `language`
- either `seed_phrase` or `sskr.groups`
- optional `passphrase` only when explicitly enabled

New backups do not store derived BIP-39 seed bytes, root XPRV values, or derived private keys.

## Security Notes

- Mnemonics and SSKR shares always include OS cryptographic randomness. Mouse-assisted generation additionally mixes pointer positions, movement, and timing into the 256-bit BIP-39 entropy; it never replaces the OS random source or claims a measurable number of random bits per movement. Its progress bar reports the 30-second ceremony duration—not an estimate of entropy bits. Movement counters continue increasing throughout the ceremony, and generation unlocks only after the timer and every minimum movement check are satisfied.
- User-entered mnemonics and mnemonic-form SSKR shares are normalized according to BIP-39 before validation, including visually equivalent Japanese input.
- Save operations write and sync a private temporary file before atomically publishing it without clobbering. Existing files, directory targets, target symlinks, and symlinked parent ancestors are refused.
- Encryption and decryption run outside the GUI thread with 60-second process timeouts and bounded ciphertext, plaintext, diagnostic, recipient-file, release-metadata, and updater-archive reads.
- Private age identities can be pasted directly for decryption; public recipients are rejected in identity fields.
- Sensitive GUI state can be cleared with `Clear Sensitive Data`. The egui frontend also cancels its in-flight worker; the native frontend serializes bridge operations and prevents edits while an operation is completing.
- Seed phrases, passphrases, identities, decrypted values, and recovery shares default to masked; clearing sensitive state also resets every reveal control.
- In-memory sensitive strings and decrypted JSON are zeroized where the Rust types allow it, but a desktop GUI can still expose secrets to OS-level memory inspection, screenshots, clipboard history, accessibility tooling, and swap. Use this on a trusted machine.
- Backup encryption strength and `age1pq...` support depend on the selected `age` binary. All platform packages ship the version documented by `scripts/fetch-age.sh`; this app shells out to `age` and does not implement AES-256-GCM or Argon2 itself.
