import AppKit
import Foundation
import SwiftUI

enum AppSection: String, CaseIterable, Identifiable {
  case create
  case open
  case recover
  case addresses
  case help

  var id: String { rawValue }

  var symbol: String {
    switch self {
    case .create: return "plus.square"
    case .open: return "folder"
    case .recover: return "point.3.connected.trianglepath.dotted"
    case .addresses: return "wallet.pass"
    case .help: return "info.circle"
    }
  }

  var titleKey: String {
    switch self {
    case .create: return "Create backup"
    case .open: return "Open backup"
    case .recover: return "Recover SSKR"
    case .addresses: return "Addresses"
    case .help: return "Help"
    }
  }

  var subtitleKey: String {
    switch self {
    case .create: return "Encrypt seed material"
    case .open: return "Decrypt and inspect"
    case .recover: return "Combine recovery shares"
    case .addresses: return "Derive public keys"
    case .help: return "Start here"
    }
  }

  var pageTitleKey: String {
    switch self {
    case .create: return "Create encrypted backup"
    case .open: return "Open encrypted backup"
    case .recover: return "Recover from SSKR shares"
    case .addresses: return "Address derivation"
    case .help: return "Help & safety guide"
    }
  }

  var pageSubtitleKey: String {
    switch self {
    case .create:
      return "Protect a new or existing BIP-39 seed with age encryption."
    case .open:
      return "Inspect a backup and load its seed material securely."
    case .recover:
      return "Reconstruct a seed from a sufficient set of recovery shares."
    case .addresses:
      return "Derive public wallet data without exposing private keys."
    case .help:
      return "Learn how to protect and recover a wallet seed."
    }
  }
}

enum BackupStage: String, CaseIterable, Identifiable {
  case seed
  case recovery
  case encryption

  var id: String { rawValue }
  var number: Int {
    switch self {
    case .seed: return 1
    case .recovery: return 2
    case .encryption: return 3
    }
  }
  var titleKey: String {
    switch self {
    case .seed: return "Seed & passphrase"
    case .recovery: return "Recovery options"
    case .encryption: return "Encryption & save"
    }
  }
}

enum MnemonicLanguage: String, CaseIterable, Identifiable {
  case english = "English"
  case simplifiedChinese = "SimplifiedChinese"
  case traditionalChinese = "TraditionalChinese"
  case japanese = "Japanese"
  case korean = "Korean"
  case spanish = "Spanish"
  case french = "French"
  case italian = "Italian"
  case czech = "Czech"
  case portuguese = "Portuguese"

  var id: String { rawValue }
  var labelKey: String {
    switch self {
    case .english: return "English"
    case .simplifiedChinese: return "Simplified Chinese"
    case .traditionalChinese: return "Traditional Chinese"
    case .japanese: return "Japanese"
    case .korean: return "Korean"
    case .spanish: return "Spanish"
    case .french: return "French"
    case .italian: return "Italian"
    case .czech: return "Czech"
    case .portuguese: return "Portuguese"
    }
  }
}

enum AddressKind: String, CaseIterable, Identifiable {
  case bitcoin = "Bitcoin"
  case ethereum = "Ethereum"
  case xrp = "XRP"
  case solana = "Solana"
  var id: String { rawValue }
}

struct AddressItem: Identifiable {
  let index: Int
  let path: String
  let address: String
  let publicKey: String
  var id: Int { index }
}

@MainActor
final class FortressModel: ObservableObject {
  let bridge = FortressBridge()

  @Published var section: AppSection = .create
  @Published var appLanguage: AppLanguage = .english
  @Published var isBusy = false
  @Published var status = ""
  @Published var statusIsError = false
  @Published var ageStatus = "Checking bundled age…"
  private var ageMode = "checking"
  private var ageVersion = ""

  @Published var generateNew = true
  @Published var backupStage: BackupStage = .seed
  @Published var mnemonicLanguage: MnemonicLanguage = .english
  @Published var wordCount = 24
  @Published var phrase = ""
  private var validatedPhrase = ""
  @Published var revealPhrase = false
  @Published var phraseValidation = ""
  @Published var passphrase = ""
  @Published var passphraseConfirmation = ""
  @Published var revealPassphrase = false
  @Published var storePassphrase = false
  @Published var sskrEnabled = false
  @Published var sskrGroups = 3
  @Published var sskrGroupThreshold = 2
  @Published var sskrSharesPerGroup = 3
  @Published var sskrRequiredShares = 2
  @Published var exportSSKRShares = true
  @Published var sskrExportParent = ""
  @Published var recipients = ""
  @Published var recipientConfirmed = false
  @Published var mouseEntropySession: MouseEntropySession?

  @Published var openPath = ""
  @Published var identity = ""
  @Published var revealIdentity = false
  @Published var decryptedPhrase = ""
  @Published var decryptedPassphrase = ""
  @Published var decryptedPassphraseStored = false
  @Published var decryptedLanguage: MnemonicLanguage = .english
  @Published var decryptedType = ""
  @Published var decryptedGroups = 0
  @Published var revealDecrypted = false
  @Published var decryptedMetadata: [String: String] = [:]
  private var decryptedSchemaVersion = 0
  private var decryptedRecoveryRule = ""

  @Published var recoveryLanguage: MnemonicLanguage = .english
  @Published var recoveryShares = ""
  @Published var recoveredPhrase = ""
  @Published var recoveryPassphrase = ""
  @Published var revealRecoveryPassphrase = false
  @Published var revealRecovered = false

  @Published var addressLanguage: MnemonicLanguage = .english
  @Published var addressPhrase = ""
  @Published var addressPassphrase = ""
  @Published var revealAddressPhrase = false
  @Published var revealAddressPassphrase = false
  @Published var addressKind: AddressKind = .bitcoin
  @Published var addressStart = 0
  @Published var addressEnd = 4
  @Published var hardenedIndex = false
  @Published var addressRows: [AddressItem] = []

  init() {
    refreshAge()
  }

  func t(_ key: String) -> String { appLanguage.text(key) }

  var seedStageReady: Bool {
    canonicalWords(phrase) == validatedPhrase
      && !validatedPhrase.isEmpty
      && passphrase == passphraseConfirmation
  }

  func openBackupStage(_ stage: BackupStage) {
    guard stage == .seed || seedStageReady else {
      setStatus(
        t(
          phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "Generate or enter a mnemonic to continue"
            : "Passphrase confirmation does not match"),
        error: true)
      backupStage = .seed
      return
    }
    status = ""
    backupStage = stage
  }

  func setStatus(_ message: String, error: Bool = false) {
    status = message
    statusIsError = error
  }

  func refreshAge() {
    ageMode = "checking"
    relocalizeAgeStatus()
    bridge.call(["operation": "start_age_update"]) { [weak self] result in
      guard let self else { return }
      switch result {
      case .success:
        self.pollAgeStatus()
      case .failure:
        self.ageMode = "available"
        self.relocalizeAgeStatus()
      }
    }
  }

  private func pollAgeStatus() {
    bridge.call(["operation": "age_update_status"]) { [weak self] result in
      guard let self else { return }
      switch result {
      case .success(let value):
        let mode = value["mode"] as? String ?? "bundled"
        if mode == "checking" {
          self.ageMode = "checking"
          self.relocalizeAgeStatus()
          DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            self.pollAgeStatus()
          }
          return
        }
        let version = value["version"] as? String ?? ""
        self.ageMode = mode
        self.ageVersion = version
        self.relocalizeAgeStatus()
      case .failure:
        self.ageMode = "available"
        self.relocalizeAgeStatus()
      }
    }
  }

  func generateMnemonic(mouseEntropyHex: String? = nil) {
    var request: [String: Any] = [
      "operation": "generate_mnemonic",
      "language": mnemonicLanguage.rawValue,
      "word_count": wordCount,
    ]
    if let mouseEntropyHex {
      request["mouse_entropy_hex"] = mouseEntropyHex
    }
    perform(
      request,
      success: { value in
        self.phrase = value["phrase"] as? String ?? ""
        self.validatedPhrase = self.canonicalWords(self.phrase)
        self.generateNew = true
        self.phraseValidation = self.t("Mnemonic checksum is valid")
        self.setStatus(
          self.t(
            mouseEntropyHex == nil
              ? "A new mnemonic was generated locally."
              : "Generated a new seed using operating-system and mouse randomness."))
      })
  }

  func beginMouseEntropyCollection() {
    guard mouseEntropySession == nil else { return }
    let session = MouseEntropySession(window: NSApp.keyWindow ?? NSApp.mainWindow)
    mouseEntropySession = session
    session.start()
  }

  func cancelMouseEntropyCollection() {
    guard let session = mouseEntropySession else { return }
    session.stop(restoreWindow: true)
    session.discardDigest()
    mouseEntropySession = nil
  }

  func finishMouseEntropyCollection() {
    guard let session = mouseEntropySession, session.isReady else { return }
    let digest = session.finalizeHex()
    session.stop(restoreWindow: true)
    mouseEntropySession = nil
    generateMnemonic(mouseEntropyHex: digest)
  }

  func validateMnemonic() {
    guard !phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
    perform(
      [
        "operation": "validate_mnemonic",
        "language": mnemonicLanguage.rawValue,
        "phrase": phrase,
      ],
      success: { value in
        self.phrase = value["canonical_phrase"] as? String ?? self.phrase
        self.validatedPhrase = self.canonicalWords(self.phrase)
        let count =
          value["word_count"] as? Int
          ?? self.phrase.split(whereSeparator: { $0.isWhitespace }).count
        self.phraseValidation = "\(count) " + self.t("words · checksum valid")
        self.setStatus(self.t("The mnemonic is valid for the selected language."))
      },
      failure: { message in
        self.validatedPhrase = ""
        self.phraseValidation = self.t("Invalid mnemonic or checksum")
        self.setStatus(message, error: true)
      })
  }

  func createIdentity(at path: String) {
    perform(
      [
        "operation": "create_identity",
        "path": path,
      ],
      success: { value in
        self.recipients = value["recipient"] as? String ?? ""
        self.recipientConfirmed = true
        self.setStatus(self.t("Private identity saved. Keep it separate from the backup."))
      })
  }

  func createBackup(at outputPath: String) {
    guard recipientConfirmed else {
      setStatus(t("Confirm that you control the matching private identity."), error: true)
      return
    }
    guard passphrase == passphraseConfirmation else {
      setStatus(t("Passphrase entries do not match."), error: true)
      return
    }
    var sskr: [String: Any] = [
      "enabled": sskrEnabled,
      "groups": sskrGroups,
      "group_threshold": sskrGroupThreshold,
      "shares_per_group": sskrSharesPerGroup,
      "required_shares_per_group": sskrRequiredShares,
    ]
    if sskrEnabled && exportSSKRShares {
      sskr["export_parent"] = sskrExportParent
    }
    perform(
      [
        "operation": "create_backup",
        "language": mnemonicLanguage.rawValue,
        "phrase": phrase,
        "passphrase": passphrase,
        "passphrase_confirmation": passphraseConfirmation,
        "store_passphrase": storePassphrase,
        "sskr": sskr,
        "recipients": recipients,
        "output_path": outputPath,
      ],
      success: { value in
        var message =
          self.t("Encrypted backup saved") + ": " + (value["path"] as? String ?? outputPath)
        if let export = value["sskr_export_path"] as? String {
          message += "\n" + self.t("SSKR shares exported") + ": " + export
        }
        self.setStatus(message)
      })
  }

  func decryptBackup() {
    perform(
      [
        "operation": "decrypt_backup",
        "path": openPath,
        "identity": identity,
      ],
      success: { value in
        self.decryptedPhrase = value["seed_phrase"] as? String ?? ""
        self.decryptedPassphrase = value["passphrase"] as? String ?? ""
        self.decryptedPassphraseStored = value["passphrase_stored"] as? Bool ?? false
        self.decryptedType = value["backup_type"] as? String ?? ""
        self.decryptedGroups = value["sskr_groups"] as? Int ?? 0
        if let rawLanguage = value["language"] as? String,
          let language = MnemonicLanguage(rawValue: rawLanguage)
        {
          self.decryptedLanguage = language
        }
        if let backup = value["backup"] as? [String: Any] {
          self.decryptedSchemaVersion = backup["schema_version"] as? Int ?? 0
          self.decryptedRecoveryRule = backup["recovery_info"] as? String ?? ""
          self.rebuildDecryptedMetadata()
        }
        self.setStatus(
          self.decryptedType == "sskr"
            ? self.t("Backup decrypted and SSKR seed reconstructed.")
            : self.t("Backup decrypted and mnemonic validated."))
      })
  }

  func loadDecryptedIntoAddresses() {
    addressLanguage = decryptedLanguage
    addressPhrase = decryptedPhrase
    addressPassphrase = decryptedPassphrase
    addressRows = []
    section = .addresses
    setStatus(
      decryptedPassphraseStored
        ? t("Recovered seed and stored passphrase loaded into Addresses.")
        : t("Recovered seed loaded. Enter the original passphrase if one was used."))
  }

  func recoverSSKR() {
    perform(
      [
        "operation": "recover_sskr",
        "language": recoveryLanguage.rawValue,
        "shares": recoveryShares,
      ],
      success: { value in
        self.recoveredPhrase = value["phrase"] as? String ?? ""
        self.setStatus(self.t("SSKR seed reconstructed and validated."))
      })
  }

  func loadRecoveredIntoAddresses() {
    addressLanguage = recoveryLanguage
    addressPhrase = recoveredPhrase
    addressPassphrase = recoveryPassphrase
    addressRows = []
    section = .addresses
    setStatus(t("Recovered seed loaded into Addresses."))
  }

  func deriveAddresses() {
    perform(
      [
        "operation": "derive_addresses",
        "language": addressLanguage.rawValue,
        "phrase": addressPhrase,
        "passphrase": addressPassphrase,
        "kind": addressKind.rawValue,
        "start": addressStart,
        "end": addressEnd,
        "hardened": addressKind == .solana ? true : hardenedIndex,
      ],
      success: { value in
        let rows = value["rows"] as? [[String: Any]] ?? []
        self.addressRows = rows.compactMap { row in
          guard let index = row["index"] as? Int else { return nil }
          return AddressItem(
            index: index,
            path: row["path"] as? String ?? "",
            address: row["address"] as? String ?? "",
            publicKey: row["public_key"] as? String ?? ""
          )
        }
        self.setStatus("\(self.addressRows.count) " + self.t("public addresses derived."))
      })
  }

  func clearSensitiveData() {
    cancelMouseEntropyCollection()
    phrase.removeAll(keepingCapacity: false)
    validatedPhrase.removeAll(keepingCapacity: false)
    passphrase.removeAll(keepingCapacity: false)
    passphraseConfirmation.removeAll(keepingCapacity: false)
    revealPassphrase = false
    recipients.removeAll(keepingCapacity: false)
    identity.removeAll(keepingCapacity: false)
    revealIdentity = false
    decryptedPhrase.removeAll(keepingCapacity: false)
    decryptedPassphrase.removeAll(keepingCapacity: false)
    recoveryShares.removeAll(keepingCapacity: false)
    recoveredPhrase.removeAll(keepingCapacity: false)
    recoveryPassphrase.removeAll(keepingCapacity: false)
    revealRecoveryPassphrase = false
    addressPhrase.removeAll(keepingCapacity: false)
    addressPassphrase.removeAll(keepingCapacity: false)
    revealAddressPhrase = false
    revealAddressPassphrase = false
    addressRows.removeAll(keepingCapacity: false)
    decryptedMetadata.removeAll(keepingCapacity: false)
    decryptedRecoveryRule.removeAll(keepingCapacity: false)
    decryptedSchemaVersion = 0
    phraseValidation = ""
    setStatus(t("Sensitive fields were cleared from application memory."))
  }

  func relocalizeVisibleText() {
    status = ""
    phraseValidation = ""
    relocalizeAgeStatus()
    rebuildDecryptedMetadata()
  }

  private func relocalizeAgeStatus() {
    switch ageMode {
    case "checking": ageStatus = t("Checking age…")
    case "updated": ageStatus = t("Verified age update") + " \(ageVersion)"
    case "bundled": ageStatus = t("Bundled age verified") + " \(ageVersion)"
    default: ageStatus = t("Bundled age available")
    }
  }

  private func rebuildDecryptedMetadata() {
    guard !decryptedType.isEmpty else { return }
    decryptedMetadata = [
      t("Backup type"): t(
        decryptedType == "sskr" ? "SSKR threshold backup" : "Direct mnemonic backup"),
      t("Mnemonic language"): t(decryptedLanguage.labelKey),
      t("Recovery rule"): localizedRecoveryRule(decryptedRecoveryRule),
      t("Schema version"): String(decryptedSchemaVersion),
    ]
  }

  private func localizedRecoveryRule(_ technical: String) -> String {
    guard decryptedType == "sskr" else { return t("Direct mnemonic backup") }
    let numbers = technical.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
    guard numbers.count >= 4 else { return t("SSKR threshold backup") }
    switch appLanguage {
    case .english:
      return
        "\(numbers[0]) of \(numbers[1]) groups · \(numbers[2]) of \(numbers[3]) shares per group"
    case .simplifiedChinese:
      return "\(numbers[1]) 组取 \(numbers[0]) 组 · 每组 \(numbers[3]) 份取 \(numbers[2]) 份"
    case .japanese:
      return "\(numbers[1]) グループ中 \(numbers[0]) · 各グループ \(numbers[3]) シェア中 \(numbers[2])"
    case .korean: return "\(numbers[1])개 그룹 중 \(numbers[0])개 · 그룹당 \(numbers[3])개 중 \(numbers[2])개"
    }
  }

  private func canonicalWords(_ value: String) -> String {
    value.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
  }

  private func userFacingError(_ technical: String) -> String {
    guard appLanguage != .english else { return technical }
    let lower = technical.lowercased()
    if lower.contains("seed phrase is invalid")
      || lower.contains("mnemonic") && lower.contains("invalid")
    {
      return t("The mnemonic is invalid for the selected wordlist or checksum.")
    }
    if lower.contains("passphrase") && lower.contains("match") {
      return t("The two passphrase entries do not match.")
    }
    if lower.contains("recipient") {
      return t("The age recipient is missing or unsupported.")
    }
    if lower.contains("identity") || lower.contains("decrypt") || lower.contains("no matching keys")
    {
      return t(
        "Decryption failed. Check that this private identity belongs to the selected backup.")
    }
    if lower.contains("duplicate sskr") || lower.contains("duplicate") && lower.contains("share") {
      return t("A duplicate SSKR share was entered. Each share must be distinct.")
    }
    if lower.contains("not enough valid sskr")
      || lower.contains("not enough") && lower.contains("share")
    {
      return t("There are not enough valid SSKR shares to satisfy the recovery thresholds.")
    }
    if lower.contains("overwrite") || lower.contains("existing file")
      || lower.contains("refusing to write")
    {
      return t("The destination already exists or is not safe to overwrite. Choose a new file.")
    }
    if lower.contains("path") || lower.contains("directory") || lower.contains("folder")
      || lower.contains("could not open")
    {
      return t("The selected file or folder cannot be used. Check its location and permissions.")
    }
    return t("The operation could not be completed. Review the selected values and try again.")
  }

  private func perform(
    _ request: [String: Any],
    success: @escaping ([String: Any]) -> Void,
    failure: ((String) -> Void)? = nil
  ) {
    guard !isBusy else { return }
    isBusy = true
    status = ""
    bridge.call(request) { [weak self] result in
      guard let self else { return }
      self.isBusy = false
      switch result {
      case .success(let value): success(value)
      case .failure(let error):
        let message = self.userFacingError(error.localizedDescription)
        if let failure { failure(message) } else { self.setStatus(message, error: true) }
      }
    }
  }
}
