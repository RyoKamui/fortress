import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct FortressRootView: View {
  @EnvironmentObject private var model: FortressModel

  var body: some View {
    ZStack {
      HStack(spacing: 0) {
        FortressSidebar()
          .frame(width: 264)

        Rectangle()
          .fill(fortressBorder)
          .frame(width: 1)

        ZStack {
          fortressBackground.ignoresSafeArea()
          VStack(spacing: 0) {
            HStack(alignment: .top) {
              PageHeading(
                title: model.t(model.section.pageTitleKey),
                subtitle: model.t(model.section.pageSubtitleKey)
              )
              Spacer(minLength: 24)
              Picker("", selection: $model.appLanguage) {
                ForEach(AppLanguage.allCases) { language in
                  Text(language.rawValue).tag(language)
                }
              }
              .labelsHidden()
              .frame(width: 132)
            }
            .padding(.horizontal, 32)
            .padding(.top, 26)
            .padding(.bottom, 22)

            Rectangle()
              .fill(fortressBorder)
              .frame(height: 1)

            ScrollView {
              VStack(spacing: 16) {
                Color.clear.frame(height: 0).id("page-top")
                if !model.status.isEmpty {
                  StatusBanner(message: model.status, isError: model.statusIsError)
                }
                switch model.section {
                case .create: CreateBackupView()
                case .open: OpenBackupView()
                case .recover: RecoverSSKRView()
                case .addresses: AddressesView()
                case .help: HelpView()
                }
              }
              .padding(.horizontal, 32)
              .padding(.top, 28)
              .padding(.bottom, 48)
              .frame(maxWidth: 1120)
              .frame(maxWidth: .infinity, alignment: .top)
            }
            .id(
              model.section == .create
                ? "\(model.section.rawValue).\(model.backupStage.rawValue)"
                : model.section.rawValue
            )
            .accessibilityIdentifier("content.\(model.section.rawValue)")
          }
          BusyOverlay(visible: model.isBusy)
        }
      }

      if let session = model.mouseEntropySession {
        MouseEntropyCeremonyView(session: session)
          .transition(.opacity)
          .zIndex(20)
      }
    }
    .animation(.easeInOut(duration: 0.18), value: model.mouseEntropySession != nil)
    .accentColor(fortressAccent)
    .foregroundColor(fortressText)
    .preferredColorScheme(.light)
    .frame(minWidth: 1080, minHeight: 740)
    .onChange(of: model.appLanguage) { language in
      model.relocalizeVisibleText()
      if model.phrase.isEmpty {
        switch language {
        case .english: model.mnemonicLanguage = .english
        case .simplifiedChinese: model.mnemonicLanguage = .simplifiedChinese
        case .japanese: model.mnemonicLanguage = .japanese
        case .korean: model.mnemonicLanguage = .korean
        }
      }
    }
    .onChange(of: model.sskrGroups) { groups in
      model.sskrGroupThreshold = min(model.sskrGroupThreshold, groups)
    }
    .onChange(of: model.sskrSharesPerGroup) { shares in
      model.sskrRequiredShares = min(model.sskrRequiredShares, shares)
    }
  }
}

struct MouseEntropyCeremonyView: View {
  @EnvironmentObject private var model: FortressModel
  @ObservedObject var session: MouseEntropySession

  var body: some View {
    GeometryReader { geometry in
      ZStack {
        LinearGradient(
          colors: [
            fortressSidebar,
            Color(red: 27 / 255, green: 28 / 255, blue: 36 / 255),
          ], startPoint: .topLeading, endPoint: .bottomTrailing
        )
        .ignoresSafeArea()

        Canvas { context, size in
          guard session.trail.count > 1 else { return }
          var path = Path()
          let first = session.trail[0]
          path.move(to: CGPoint(x: first.x, y: size.height - first.y))
          for point in session.trail.dropFirst() {
            path.addLine(to: CGPoint(x: point.x, y: size.height - point.y))
          }
          context.stroke(
            path,
            with: .color(Color(red: 132 / 255, green: 132 / 255, blue: 242 / 255).opacity(0.72)),
            style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
          if let last = session.trail.last {
            let center = CGPoint(x: last.x, y: size.height - last.y)
            context.fill(
              Path(ellipseIn: CGRect(x: center.x - 7, y: center.y - 7, width: 14, height: 14)),
              with: .color(fortressAccentBorder))
            context.stroke(
              Path(ellipseIn: CGRect(x: center.x - 14, y: center.y - 14, width: 28, height: 28)),
              with: .color(Color(red: 158 / 255, green: 158 / 255, blue: 255 / 255).opacity(0.55)),
              lineWidth: 2)
          }
        }
        .allowsHitTesting(false)

        VStack(spacing: 0) {
          Spacer(minLength: 24)
          VStack(spacing: 10) {
            Image(systemName: "cursorarrow.motionlines")
              .font(.system(size: 30, weight: .semibold))
              .foregroundColor(fortressAccentBorder)
            Text(model.t("Mouse entropy collection"))
              .font(.system(size: 30, weight: .bold, design: .rounded))
              .foregroundColor(fortressSidebarText)
            Text(model.t("Move your pointer unpredictably across the entire screen."))
              .font(.system(size: 17))
              .foregroundColor(fortressSidebarText)
            Text(
              model.t(
                "Fortress combines these movement samples with secure operating-system randomness."
              )
            )
            .font(.system(size: 14))
            .foregroundColor(fortressSidebarMuted)
            Text(model.t("30-second minimum · Cover the screen · Change direction and speed"))
              .font(.system(size: 14, weight: .semibold))
              .foregroundColor(fortressAccentBorder)
              .padding(.top, 2)

            VStack(spacing: 8) {
              HStack {
                Text(model.t("Collection progress"))
                  .font(.system(size: 14, weight: .semibold))
                Spacer()
                Text("\(Int(session.progress * 100))%")
                  .font(.system(size: 13, weight: .semibold, design: .monospaced))
              }
              .foregroundColor(fortressSidebarText)
              ProgressView(value: session.progress)
                .progressViewStyle(.linear)
                .tint(fortressAccent)
                .animation(.linear(duration: 0.08), value: session.progress)
              Text(timeText)
                .font(.system(size: 13))
                .foregroundColor(fortressSidebarMuted)
              ForEach(metricLines, id: \.self) { line in
                Text(line)
                  .font(.system(size: 13, design: .monospaced))
                  .foregroundColor(fortressSidebarMuted)
              }
            }
            .frame(maxWidth: 720)
            .padding(.top, 18)

            Text(guidanceText)
              .font(.system(size: 15, weight: .medium))
              .foregroundColor(session.isReady ? fortressAccentBorder : fortressSidebarMuted)
              .padding(.top, 4)

            HStack(spacing: 12) {
              Button {
                model.cancelMouseEntropyCollection()
              } label: {
                Text(model.t("Cancel"))
                  .font(.system(size: 14, weight: .semibold))
                  .foregroundColor(fortressSidebarText)
                  .padding(.horizontal, 20)
                  .frame(height: 38)
                  .background(Color.white.opacity(0.08))
                  .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                  .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                      .stroke(fortressSidebarMuted.opacity(0.48), lineWidth: 1))
              }
              .buttonStyle(.plain)
              .keyboardShortcut(.cancelAction)
              Button {
                model.finishMouseEntropyCollection()
              } label: {
                Text(model.t("Generate seed"))
                  .font(.system(size: 14, weight: .semibold))
                  .foregroundColor(session.isReady ? Color.white : fortressSidebarMuted)
                  .padding(.horizontal, 20)
                  .frame(height: 38)
                  .background(session.isReady ? fortressAccent : Color.white.opacity(0.06))
                  .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                  .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                      .stroke(
                        session.isReady ? fortressAccent : fortressSidebarMuted.opacity(0.28),
                        lineWidth: 1))
              }
              .buttonStyle(.plain)
              .disabled(!session.isReady)
            }
            .padding(.top, 10)
            Text(model.t("Press Esc to cancel"))
              .font(.system(size: 12.5))
              .foregroundColor(fortressSidebarMuted)
          }
          .padding(.horizontal, 36)
          Spacer(minLength: 24)
        }
      }
      .frame(width: geometry.size.width, height: geometry.size.height)
    }
    .accessibilityIdentifier("mouse-entropy-ceremony")
  }

  private var guidanceText: String {
    if session.isReady {
      return model.t("Enough movement collected. You can generate the seed now.")
    }
    if session.movementRequirementsMet {
      return model.t("Movement checks complete—keep moving until the timer ends.")
    }
    return model.t("Keep moving—use wide, irregular paths and vary your speed.")
  }

  private var timeText: String {
    let remaining = max(Int(ceil(MouseEntropySession.minimumDuration - session.elapsed)), 0)
    if remaining == 0 {
      switch model.appLanguage {
      case .english: return "30-second minimum complete"
      case .simplifiedChinese: return "已满足 30 秒最低时长"
      case .japanese: return "30 秒の最低時間を満たしました"
      case .korean: return "30초 최소 시간을 충족했습니다"
      }
    }
    switch model.appLanguage {
    case .english: return "Minimum time: \(remaining) seconds remaining"
    case .simplifiedChinese: return "最低时长：还需 \(remaining) 秒"
    case .japanese: return "最低時間：残り \(remaining) 秒"
    case .korean: return "최소 시간: \(remaining)초 남음"
    }
  }

  private var metricLines: [String] {
    let travel = String(format: "%.1f", session.travelInDiagonals)
    let coveragePercent = session.coverageCount * 100 / session.totalCells
    switch model.appLanguage {
    case .english:
      return [
        "Samples \(session.sampleCount) · Travel \(travel) diagonals",
        "Screen coverage \(coveragePercent)% · Turns \(session.turnCount) · Speed ranges \(session.speedRangeCount)/4",
      ]
    case .simplifiedChinese:
      return [
        "移动样本 \(session.sampleCount) · 移动距离 \(travel) 个屏幕对角线",
        "屏幕覆盖 \(coveragePercent)% · 方向变化 \(session.turnCount) · 速度范围 \(session.speedRangeCount)/4",
      ]
    case .japanese:
      return [
        "移動サンプル \(session.sampleCount) · 移動距離 \(travel) 画面対角",
        "画面カバー率 \(coveragePercent)% · 方向転換 \(session.turnCount) · 速度域 \(session.speedRangeCount)/4",
      ]
    case .korean:
      return [
        "이동 샘플 \(session.sampleCount) · 이동 거리 \(travel) 화면 대각선",
        "화면 범위 \(coveragePercent)% · 방향 전환 \(session.turnCount) · 속도 범위 \(session.speedRangeCount)/4",
      ]
    }
  }
}

struct FortressSidebar: View {
  @EnvironmentObject private var model: FortressModel

  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: 12) {
        FortressLogoView()
        Text("Fortress")
          .font(.system(size: 21, weight: .bold, design: .rounded))
          .foregroundColor(fortressSidebarText)
        Spacer()
      }
      .padding(.horizontal, 18)
      .padding(.top, 22)
      .padding(.bottom, 24)

      VStack(spacing: 6) {
        ForEach(AppSection.allCases) { section in
          Button {
            model.section = section
            model.status = ""
          } label: {
            HStack(spacing: 13) {
              Image(systemName: section.symbol)
                .font(.system(size: 17, weight: .medium))
                .foregroundColor(
                  model.section == section
                    ? Color(red: 158 / 255, green: 158 / 255, blue: 255 / 255)
                    : fortressSidebarMuted
                )
                .frame(width: 24)
              VStack(alignment: .leading, spacing: 2) {
                Text(model.t(section.titleKey))
                  .font(
                    .system(size: 14.5, weight: model.section == section ? .semibold : .regular)
                  )
                  .foregroundColor(
                    model.section == section
                      ? fortressSidebarText
                      : Color(red: 213 / 255, green: 216 / 255, blue: 223 / 255))
                Text(model.t(section.subtitleKey))
                  .font(.system(size: 11.5))
                  .foregroundColor(fortressSidebarMuted)
                  .lineLimit(1)
              }
              Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .frame(maxWidth: .infinity, minHeight: 56, maxHeight: 56, alignment: .leading)
            .contentShape(Rectangle())
            .background(
              model.section == section
                ? Color(red: 31 / 255, green: 33 / 255, blue: 42 / 255)
                : Color.clear
            )
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay(alignment: .leading) {
              if model.section == section {
                RoundedRectangle(cornerRadius: 2, style: .continuous)
                  .fill(fortressAccent)
                  .frame(width: 3, height: 36)
              }
            }
          }
          .buttonStyle(.plain)
          .frame(maxWidth: .infinity, alignment: .leading)
          .contentShape(Rectangle())
          .accessibilityIdentifier("sidebar.\(section.rawValue)")
        }
      }
      .padding(.horizontal, 12)

      Spacer(minLength: 20)

      VStack(alignment: .leading, spacing: 13) {
        Label(model.ageStatus, systemImage: "checkmark.shield")
          .font(.system(size: 11.5))
          .foregroundColor(fortressSidebarMuted)
          .lineLimit(2)
        Label(
          model.t("Secrets remain in this app's memory only while needed"),
          systemImage: "memorychip"
        )
        .font(.system(size: 11.5))
        .foregroundColor(fortressSidebarMuted)
        .lineLimit(3)
        Button(role: .destructive) {
          model.clearSensitiveData()
        } label: {
          Label(model.t("Clear sensitive data"), systemImage: "trash")
            .font(.system(size: 13, weight: .semibold))
            .foregroundColor(Color(red: 248 / 255, green: 113 / 255, blue: 113 / 255))
        }
        .buttonStyle(.plain)
      }
      .padding(18)
    }
    .background(fortressSidebar)
  }
}

struct CreateBackupView: View {
  @EnvironmentObject private var model: FortressModel

  var body: some View {
    VStack(spacing: 16) {
      BackupStageBar()

      switch model.backupStage {
      case .seed:
        seedCard
      case .recovery:
        recoveryCard
      case .encryption:
        encryptionCard
      }

      HStack(spacing: 10) {
        if model.backupStage != .seed {
          Button(
            model.t(model.backupStage == .recovery ? "Back to seed" : "Back to recovery")
          ) {
            model.openBackupStage(model.backupStage == .recovery ? .seed : .recovery)
          }
          .controlSize(.large)
        }
        Spacer()
        if model.backupStage != .encryption {
          Button(
            model.t(
              model.backupStage == .seed
                ? "Continue to recovery" : "Continue to encryption")
          ) {
            model.openBackupStage(model.backupStage == .seed ? .recovery : .encryption)
          }
          .fortressPrimaryButton()
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .topLeading)
    .accessibilityIdentifier("page.create")
  }

  private var seedCard: some View {
    FortressCard {
      VStack(alignment: .leading, spacing: 16) {
        SectionHeading(
          model.t("Seed material"), symbol: "key.horizontal",
          subtitle: model.t("Choose the mnemonic and optional BIP-39 passphrase to protect."))

        FormRow(model.t("Source")) {
          Picker("", selection: $model.generateNew) {
            Text(model.t("Generate new")).tag(true)
            Text(model.t("Import existing")).tag(false)
          }
          .pickerStyle(.segmented)
          .labelsHidden()
          .frame(maxWidth: 360)
        }
        FormRow(model.t("Language")) {
          Picker("", selection: $model.mnemonicLanguage) {
            ForEach(MnemonicLanguage.allCases) { language in
              Text(model.t(language.labelKey)).tag(language)
            }
          }
          .labelsHidden()
          .frame(width: 220)
          if model.generateNew {
            Picker("", selection: $model.wordCount) {
              ForEach([12, 15, 18, 21, 24], id: \.self) { count in Text("\(count)").tag(count) }
            }
            .labelsHidden()
            .frame(width: 78)
          }
        }
        if model.generateNew {
          FormBlock(model.t("Randomness")) {
            HStack(spacing: 10) {
              Button(model.t("Generate seed")) { model.generateMnemonic() }
                .controlSize(.large)
              Button(model.t("Add mouse randomness")) { model.beginMouseEntropyCollection() }
                .controlSize(.large)
            }
            Text(
              model.t(
                "Mouse mode opens a full-screen canvas and also uses secure system randomness."
              )
            )
            .font(.system(size: 12.5))
            .foregroundColor(fortressMutedText)
          }
        }

        FormBlock(model.t("Seed phrase")) {
          if !model.generateNew {
            Group {
              if model.revealPhrase {
                TextEditor(text: $model.phrase)
              } else {
                SecureField(model.t("Seed phrase"), text: $model.phrase)
              }
            }
            .font(.system(size: 14, design: .monospaced))
            .fortressField()
          }
          Toggle(
            model.t(model.generateNew ? "Reveal generated phrase" : "Reveal seed phrase"),
            isOn: $model.revealPhrase
          )
          .toggleStyle(.checkbox)
          MnemonicWordsView(phrase: model.phrase, revealed: model.revealPhrase)
          HStack {
            if !model.phraseValidation.isEmpty {
              Label(
                model.phraseValidation,
                systemImage: model.phraseValidation.contains(
                  model.t("Invalid mnemonic or checksum"))
                  ? "xmark.circle.fill" : "checkmark.circle.fill"
              )
              .font(.system(size: 12.5, weight: .medium))
              .foregroundColor(
                model.phraseValidation.contains(model.t("Invalid mnemonic or checksum"))
                  ? fortressError : fortressSuccess)
            }
            Spacer()
            Button(model.t("Validate mnemonic")) { model.validateMnemonic() }
              .disabled(model.phrase.isEmpty)
          }
        }

        Divider()
        FormRow(model.t("Passphrase")) {
          Group {
            if model.revealPassphrase {
              TextField(model.t("Optional BIP-39 passphrase"), text: $model.passphrase)
            } else {
              SecureField(model.t("Optional BIP-39 passphrase"), text: $model.passphrase)
            }
          }
          .fortressField()
        }
        FormRow(model.t("Confirm passphrase")) {
          Group {
            if model.revealPassphrase {
              TextField(
                model.t("Enter the same passphrase again"), text: $model.passphraseConfirmation)
            } else {
              SecureField(
                model.t("Enter the same passphrase again"), text: $model.passphraseConfirmation)
            }
          }
          .fortressField()
        }
        FormActions {
          Toggle(model.t("Reveal passphrase"), isOn: $model.revealPassphrase)
            .toggleStyle(.checkbox)
          Toggle(model.t("Include passphrase in encrypted backup"), isOn: $model.storePassphrase)
            .toggleStyle(.checkbox)
        }
        FortressCallout(
          symbol: "exclamationmark.triangle", title: "BIP-39",
          message: model.t(
            "Every passphrase creates a different valid wallet. Fortress can confirm matching input, but only a known address proves it is the intended wallet."
          ), warning: true)
      }
    }
  }

  private var recoveryCard: some View {
    FortressCard {
      VStack(alignment: .leading, spacing: 16) {
        SectionHeading(
          model.t("Recovery format"), symbol: "point.3.connected.trianglepath.dotted",
          subtitle: model.t(
            "Optionally replace the stored mnemonic with threshold recovery shares."))
        FormRow("SSKR") {
          Toggle(model.t("Split seed into recovery shares"), isOn: $model.sskrEnabled)
            .toggleStyle(.checkbox)
        }
        if model.sskrEnabled {
          Divider()
          FormRow(model.t("Groups")) {
            Stepper(
              "\(model.t("Create")): \(model.sskrGroups)", value: $model.sskrGroups, in: 1...16)
            Stepper(
              "\(model.t("Require")): \(model.sskrGroupThreshold)",
              value: $model.sskrGroupThreshold, in: 1...model.sskrGroups)
          }
          FormRow(model.t("Shares per group")) {
            Stepper(
              "\(model.t("Create")): \(model.sskrSharesPerGroup)",
              value: $model.sskrSharesPerGroup, in: 1...16)
            Stepper(
              "\(model.t("Require")): \(model.sskrRequiredShares)",
              value: $model.sskrRequiredShares, in: 1...model.sskrSharesPerGroup)
          }
          FormRow(model.t("Separate storage")) {
            Toggle(
              model.t("Export each SSKR share as a separate file"),
              isOn: $model.exportSSKRShares
            )
            .toggleStyle(.checkbox)
          }
          if model.exportSSKRShares {
            FormRow(model.t("Export folder")) {
              Text(
                model.sskrExportParent.isEmpty
                  ? model.t("No folder selected") : model.sskrExportParent
              )
              .font(.system(size: 12, design: .monospaced))
              .foregroundColor(fortressMutedText)
              .lineLimit(1)
              .frame(maxWidth: .infinity, alignment: .leading)
              Button(model.t("Choose folder")) { chooseFolder { model.sskrExportParent = $0 } }
                .controlSize(.large)
            }
          } else {
            FortressCallout(
              symbol: "externaldrive.badge.exclamationmark", title: "SSKR",
              message: model.t(
                "Without separate export, all SSKR shares remain together inside one encrypted file; that file is still a single point of loss."
              ), warning: true)
          }
        }
      }
    }
  }

  private var encryptionCard: some View {
    FortressCard {
      VStack(alignment: .leading, spacing: 16) {
        SectionHeading(
          model.t("Encrypt and save"), symbol: "lock.shield",
          subtitle: model.t(
            "Select who can decrypt the backup and where the encrypted file is written."))
        FormRow(model.t("Recipient")) {
          TextField(
            model.t("Paste an age1… recipient or choose a recipient file"), text: $model.recipients
          )
          .font(.system(size: 13, design: .monospaced))
          .fortressField()
          Button(model.t("Choose file")) { chooseFile { model.recipients = $0 } }
            .controlSize(.large)
        }
        FormActions {
          Toggle(
            model.t("I verified that I control this recipient's private identity"),
            isOn: $model.recipientConfirmed
          )
          .toggleStyle(.checkbox)
        }
        Divider()
        Text(
          model.t(
            "Need a key? Create a private age identity locally; its public recipient will be filled in automatically."
          )
        )
        .font(.system(size: 14))
        .foregroundColor(fortressMutedText)
        FormActions {
          Button(model.t("Create age identity")) {
            saveFile(defaultName: "age-identity.txt", allowedExtension: "txt") {
              model.createIdentity(at: $0)
            }
          }
          .controlSize(.large)
        }
        FormActions {
          Button(model.t("Encrypt and save")) {
            saveFile(defaultName: "fortress-backup.age", allowedExtension: "age") {
              model.createBackup(at: $0)
            }
          }
          .fortressPrimaryButton()
          .disabled(
            model.phrase.isEmpty || model.recipients.isEmpty || !model.recipientConfirmed
              || (model.sskrEnabled && model.exportSSKRShares && model.sskrExportParent.isEmpty))
        }
      }
    }
  }
}

struct BackupStageBar: View {
  @EnvironmentObject private var model: FortressModel

  var body: some View {
    HStack(spacing: 10) {
      ForEach(BackupStage.allCases) { stage in
        Button {
          model.openBackupStage(stage)
        } label: {
          HStack(spacing: 8) {
            Text(model.backupStage == stage ? "\(stage.number)" : "•")
              .font(.system(size: 13, weight: .bold, design: .rounded))
            Text(model.t(stage.titleKey))
              .font(.system(size: 14, weight: model.backupStage == stage ? .semibold : .regular))
              .lineLimit(1)
            Spacer(minLength: 0)
          }
          .padding(.horizontal, 14)
          .frame(maxWidth: .infinity, minHeight: 42, alignment: .leading)
          .contentShape(Rectangle())
          .background(model.backupStage == stage ? fortressAccent.opacity(0.10) : Color.clear)
          .foregroundColor(model.backupStage == stage ? fortressAccent : fortressMutedText)
          .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
          .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
              .stroke(
                model.backupStage == stage
                  ? fortressAccent.opacity(0.72) : fortressBorder,
                lineWidth: 1)
          )
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity)
        .disabled(stage != .seed && !model.seedStageReady)
        .accessibilityIdentifier("backup-stage.\(stage.rawValue)")
      }
    }
  }
}

struct OpenBackupView: View {
  @EnvironmentObject private var model: FortressModel

  var body: some View {
    VStack(spacing: 16) {
      FortressCard {
        VStack(alignment: .leading, spacing: 16) {
          SectionHeading(
            model.t("Unlock backup"), symbol: "folder",
            subtitle: model.t(
              "Choose the encrypted file and supply a matching private age identity."))
          FormRow(model.t("Backup file")) {
            TextField(model.t("Backup file"), text: $model.openPath).fortressField()
            Button(model.t("Open file")) {
              chooseFile(extensions: ["age"]) { model.openPath = $0 }
            }
            .controlSize(.large)
          }
          FormRow(model.t("Private identity")) {
            Group {
              if model.revealIdentity {
                TextField(
                  model.t("Paste AGE-SECRET-KEY-… or choose an identity file"),
                  text: $model.identity)
              } else {
                SecureField(
                  model.t("Paste AGE-SECRET-KEY-… or choose an identity file"),
                  text: $model.identity)
              }
            }
            .fortressField()
            Button(model.t("Choose file")) { chooseFile { model.identity = $0 } }
              .controlSize(.large)
          }
          FormActions {
            Toggle(model.t("Reveal identity"), isOn: $model.revealIdentity)
              .toggleStyle(.checkbox)
          }
          FormActions {
            Button(model.t("Decrypt backup")) { model.decryptBackup() }.fortressPrimaryButton()
              .disabled(model.openPath.isEmpty || model.identity.isEmpty)
          }
        }
      }

      if !model.decryptedPhrase.isEmpty {
        FortressCard {
          VStack(alignment: .leading, spacing: 16) {
            SectionHeading(
              model.t("Decrypted contents"), symbol: "checkmark.shield",
              subtitle: model.t("Sensitive values remain masked until you explicitly reveal them."))
            LazyVGrid(
              columns: [GridItem(.adaptive(minimum: 190), spacing: 10)],
              alignment: .leading,
              spacing: 10
            ) {
              ForEach(model.decryptedMetadata.keys.sorted(), id: \.self) { key in
                VStack(alignment: .leading, spacing: 3) {
                  Text(key).font(.caption).foregroundColor(fortressMutedText)
                  Text(model.decryptedMetadata[key] ?? "").font(
                    .system(size: 12.5, weight: .medium)
                  )
                  .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 10).padding(.vertical, 7)
                .frame(maxWidth: .infinity, minHeight: 54, alignment: .leading)
                .background(fortressAccentSoft).clipShape(
                  RoundedRectangle(cornerRadius: 8))
              }
            }
            if model.decryptedGroups > 0 {
              Label(
                "\(model.decryptedGroups) " + model.t("SSKR groups reconstructed automatically"),
                systemImage: "point.3.connected.trianglepath.dotted"
              )
              .foregroundColor(fortressAccent)
            }
            Toggle(
              model.t("Reveal sensitive values"),
              isOn: $model.revealDecrypted
            ).toggleStyle(.checkbox)
            MnemonicWordsView(phrase: model.decryptedPhrase, revealed: model.revealDecrypted)
            FortressCallout(
              symbol: model.decryptedPassphraseStored
                ? "checkmark.circle" : "exclamationmark.triangle",
              title: "BIP-39",
              message: model.t(
                model.decryptedPassphraseStored
                  ? "Passphrase was stored in this backup."
                  : "No passphrase was stored. Enter the original one before deriving if the wallet used one."
              ),
              warning: !model.decryptedPassphraseStored
            )
            FormActions {
              Button(model.t("Open address derivation")) { model.loadDecryptedIntoAddresses() }
                .fortressPrimaryButton()
            }
          }
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .topLeading)
    .accessibilityIdentifier("page.open")
  }
}

struct RecoverSSKRView: View {
  @EnvironmentObject private var model: FortressModel
  var body: some View {
    VStack(spacing: 16) {
      FortressCard {
        VStack(alignment: .leading, spacing: 16) {
          SectionHeading(
            model.t("Recovery shares"), symbol: "point.3.connected.trianglepath.dotted",
            subtitle: model.t("Paste one unique hexadecimal or mnemonic SSKR share per line."))
          FormRow(model.t("Share language")) {
            Picker("", selection: $model.recoveryLanguage) {
              ForEach(MnemonicLanguage.allCases) { language in
                Text(model.t(language.labelKey)).tag(language)
              }
            }.labelsHidden().frame(width: 220)
          }
          FormBlock(model.t("SSKR shares")) {
            TextEditor(text: $model.recoveryShares)
              .font(.system(size: 12.5, design: .monospaced))
              .frame(minHeight: 200)
              .overlay(RoundedRectangle(cornerRadius: 7).stroke(fortressBorder))
          }
        }
      }
      FortressCard {
        VStack(alignment: .leading, spacing: 16) {
          SectionHeading(
            model.t("Wallet passphrase"), symbol: "key.horizontal",
            subtitle: model.t("Enter the original BIP-39 passphrase if this wallet used one."))
          FormRow(model.t("Passphrase")) {
            Group {
              if model.revealRecoveryPassphrase {
                TextField(model.t("Optional BIP-39 passphrase"), text: $model.recoveryPassphrase)
              } else {
                SecureField(model.t("Optional BIP-39 passphrase"), text: $model.recoveryPassphrase)
              }
            }
            .fortressField()
          }
          FormActions {
            Toggle(model.t("Reveal passphrase"), isOn: $model.revealRecoveryPassphrase)
              .toggleStyle(.checkbox)
          }
          FormActions {
            Button(model.t("Recover seed")) { model.recoverSSKR() }.fortressPrimaryButton()
              .disabled(model.recoveryShares.isEmpty)
          }
        }
      }
      if !model.recoveredPhrase.isEmpty {
        FortressCard {
          VStack(alignment: .leading, spacing: 16) {
            SectionHeading(model.t("Recovered seed"), symbol: "checkmark.shield")
            Toggle(
              model.revealRecovered ? model.t("Hide words") : model.t("Reveal words"),
              isOn: $model.revealRecovered
            ).toggleStyle(.checkbox)
            MnemonicWordsView(phrase: model.recoveredPhrase, revealed: model.revealRecovered)
            FormActions {
              Button(model.t("Open address derivation")) { model.loadRecoveredIntoAddresses() }
                .fortressPrimaryButton()
            }
          }
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .topLeading)
    .accessibilityIdentifier("page.recover")
  }
}

struct AddressesView: View {
  @EnvironmentObject private var model: FortressModel
  var body: some View {
    VStack(spacing: 16) {
      FortressCard {
        VStack(alignment: .leading, spacing: 17) {
          SectionHeading(
            model.t("Derivation inputs"), symbol: "wallet.pass",
            subtitle: model.t("Use a loaded backup or paste a valid BIP-39 mnemonic manually."))
          FormRow(model.t("Language")) {
            Picker("", selection: $model.addressLanguage) {
              ForEach(MnemonicLanguage.allCases) { language in
                Text(model.t(language.labelKey)).tag(language)
              }
            }.labelsHidden().frame(width: 220)
            Text(model.t("Address type")).foregroundColor(fortressMutedText)
            Picker("", selection: $model.addressKind) {
              ForEach(AddressKind.allCases) { kind in Text(kind.rawValue).tag(kind) }
            }.labelsHidden().frame(width: 170)
          }
          FormBlock(model.t("Seed phrase")) {
            Group {
              if model.revealAddressPhrase {
                TextEditor(text: $model.addressPhrase)
                  .frame(minHeight: 82)
                  .overlay(
                    RoundedRectangle(cornerRadius: 7).stroke(fortressBorder))
              } else {
                SecureField(model.t("Seed phrase"), text: $model.addressPhrase)
                  .fortressField()
              }
            }
            .font(.system(size: 13, design: .monospaced))
            Toggle(model.t("Reveal seed phrase"), isOn: $model.revealAddressPhrase)
              .toggleStyle(.checkbox)
          }
          FormRow(model.t("Passphrase")) {
            Group {
              if model.revealAddressPassphrase {
                TextField(model.t("Optional BIP-39 passphrase"), text: $model.addressPassphrase)
              } else {
                SecureField(model.t("Optional BIP-39 passphrase"), text: $model.addressPassphrase)
              }
            }
            .fortressField()
          }
          FormActions {
            Toggle(model.t("Reveal passphrase"), isOn: $model.revealAddressPassphrase)
              .toggleStyle(.checkbox)
          }
          FormRow(model.t("Index range")) {
            Text(model.t("Start")).foregroundColor(fortressMutedText)
            TextField("0", value: $model.addressStart, formatter: NumberFormatter.nonNegative)
              .fortressField().frame(width: 90)
            Text(model.t("End")).foregroundColor(fortressMutedText)
            TextField("4", value: $model.addressEnd, formatter: NumberFormatter.nonNegative)
              .fortressField().frame(width: 90)
          }
          if model.addressKind != .solana {
            FormActions {
              Toggle(model.t("Harden final index"), isOn: $model.hardenedIndex).toggleStyle(
                .checkbox)
            }
          }
          FortressCallout(
            symbol: "eye.slash", title: model.t("Public key"),
            message: model.t("No private keys are displayed or returned by the Rust core."))
          FormActions {
            Button(model.t("Derive addresses")) { model.deriveAddresses() }.fortressPrimaryButton()
              .disabled(model.addressPhrase.isEmpty)
          }
        }
      }
      if !model.addressRows.isEmpty {
        FortressCard {
          VStack(alignment: .leading, spacing: 14) {
            SectionHeading(
              model.t("Public results"), symbol: "wallet.pass",
              subtitle: model.t(
                "Addresses and public keys are safe to share; no private keys are displayed."))
            ScrollView(.horizontal) {
              VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 12) {
                  Text(model.t("Index")).frame(width: 50, alignment: .leading)
                  Text(model.t("Path")).frame(width: 190, alignment: .leading)
                  Text(model.t("Address")).frame(width: 340, alignment: .leading)
                  Text(model.t("Public key")).frame(width: 420, alignment: .leading)
                }.font(.system(size: 12, weight: .semibold)).foregroundColor(fortressMutedText)
                  .padding(
                    .bottom, 10)
                Divider()
                ForEach(model.addressRows) { row in
                  HStack(alignment: .top, spacing: 12) {
                    Text("\(row.index)").frame(width: 50, alignment: .leading)
                    Text(row.path).frame(width: 190, alignment: .leading)
                    Text(row.address).frame(width: 340, alignment: .leading)
                      .textSelection(.enabled)
                    Text(row.publicKey).frame(width: 420, alignment: .leading)
                      .textSelection(.enabled)
                  }.font(.system(size: 11.5, design: .monospaced)).padding(.vertical, 9)
                  Divider()
                }
              }
            }
          }
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .topLeading)
    .accessibilityIdentifier("page.addresses")
  }
}

struct HelpView: View {
  @EnvironmentObject private var model: FortressModel
  var body: some View {
    VStack(spacing: 16) {
      FortressCallout(
        symbol: "exclamationmark.shield", title: model.t("Read this before storing real funds"),
        message: model.t(
          "A backup is useful only after you have decrypted it, reconstructed its seed material, and matched a known wallet address."
        ), warning: true)
      ForEach(model.appLanguage.helpTopics) { topic in
        FortressCard {
          VStack(alignment: .leading, spacing: 14) {
            SectionHeading(topic.title, symbol: topic.symbol)
            Text(topic.introduction).font(.system(size: 14.5)).foregroundColor(fortressMutedText)
              .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 9) {
              ForEach(topic.bullets, id: \.self) { bullet in
                HStack(alignment: .top, spacing: 10) {
                  Circle().fill(fortressAccent).frame(width: 5, height: 5).padding(.top, 7)
                  Text(bullet).font(.system(size: 14)).fixedSize(horizontal: false, vertical: true)
                }
              }
            }
            FortressCallout(symbol: "lightbulb", title: topic.exampleTitle, message: topic.example)
          }
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .topLeading)
    .accessibilityIdentifier("page.help")
  }
}

private func chooseFile(extensions: [String]? = nil, completion: @escaping (String) -> Void) {
  let panel = NSOpenPanel()
  panel.canChooseFiles = true
  panel.canChooseDirectories = false
  panel.allowsMultipleSelection = false
  if let extensions {
    panel.allowedContentTypes = extensions.compactMap { UTType(filenameExtension: $0) }
  }
  if panel.runModal() == .OK, let url = panel.url { completion(url.path) }
}

private func chooseFolder(completion: @escaping (String) -> Void) {
  let panel = NSOpenPanel()
  panel.canChooseFiles = false
  panel.canChooseDirectories = true
  panel.canCreateDirectories = true
  panel.allowsMultipleSelection = false
  if panel.runModal() == .OK, let url = panel.url { completion(url.path) }
}

private func saveFile(
  defaultName: String, allowedExtension: String, completion: @escaping (String) -> Void
) {
  let panel = NSSavePanel()
  panel.nameFieldStringValue = defaultName
  if let contentType = UTType(filenameExtension: allowedExtension) {
    panel.allowedContentTypes = [contentType]
  }
  panel.canCreateDirectories = true
  if panel.runModal() == .OK, let url = panel.url { completion(url.path) }
}

extension NumberFormatter {
  static let nonNegative: NumberFormatter = {
    let formatter = NumberFormatter()
    formatter.numberStyle = .none
    formatter.minimum = 0
    formatter.maximum = 4_294_967_295
    return formatter
  }()
}
