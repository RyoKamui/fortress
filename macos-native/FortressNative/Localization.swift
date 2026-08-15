import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
  case english = "English"
  case simplifiedChinese = "简体中文"
  case japanese = "日本語"
  case korean = "한국어"

  var id: String { rawValue }

  func text(_ key: String) -> String {
    if self == .english { return key }
    return Self.translations[self]?[key] ?? key
  }

  static let translations: [AppLanguage: [String: String]] = [
    .simplifiedChinese: [
      "Create backup": "创建备份",
      "Open backup": "打开备份",
      "Recover SSKR": "恢复 SSKR",
      "Addresses": "派生地址",
      "Help": "使用指南",
      "Encrypt seed material": "加密助记词备份",
      "Decrypt and inspect": "解密并查看内容",
      "Combine recovery shares": "组合 SSKR 份额",
      "Derive public keys": "生成公开地址",
      "Start here": "从这里开始",
      "Clear sensitive data": "清除敏感信息",
      "Secrets remain in this app's memory only while needed": "敏感信息仅在需要时保留于应用内存",
      "Checking age…": "正在检查 age…",
      "Checking bundled age…": "正在检查内置 age…",
      "Verified age update": "已验证 age 更新",
      "Bundled age verified": "已验证内置 age",
      "Bundled age available": "可使用内置 age",
      "A new mnemonic was generated locally.": "已在本机生成新的助记词。",
      "Generated a new seed using operating-system and mouse randomness.":
        "已使用系统安全随机源与鼠标随机性生成新的助记词。",
      "Mnemonic checksum is valid": "助记词词表与校验和均有效",
      "words · checksum valid": "个词 · 校验和有效",
      "Invalid mnemonic or checksum": "助记词或校验和无效",
      "The mnemonic is valid for the selected language.": "助记词属于所选词表，且校验和有效。",
      "Private identity saved. Keep it separate from the backup.": "私密 identity 已保存。请与加密备份分开保管。",
      "Confirm that you control the matching private identity.":
        "请确认你掌握与 recipient 配对的私密 identity。",
      "Passphrase entries do not match.": "两次输入的附加密码不一致。",
      "Encrypted backup saved": "加密备份已保存",
      "SSKR shares exported": "SSKR 份额已分别导出",
      "Backup decrypted and SSKR seed reconstructed.": "备份已解密，并已重组 SSKR 助记词。",
      "Backup decrypted and mnemonic validated.": "备份已解密，助记词校验通过。",
      "Backup type": "备份类型",
      "Mnemonic language": "助记词语言",
      "Recovery rule": "恢复门限",
      "Schema version": "格式版本",
      "Direct mnemonic backup": "直接助记词备份",
      "SSKR threshold backup": "SSKR 门限备份",
      "Recovered seed and stored passphrase loaded into Addresses.": "已将恢复的助记词及备份中的附加密码载入地址派生。",
      "Recovered seed loaded. Enter the original passphrase if one was used.":
        "助记词已载入。若原钱包使用过附加密码，请输入完全相同的内容。",
      "SSKR seed reconstructed and validated.": "SSKR 助记词已重组并通过校验。",
      "Recovered seed loaded into Addresses.": "恢复的助记词已载入地址派生。",
      "public addresses derived.": "个公开地址已派生。",
      "Sensitive fields were cleared from application memory.": "敏感字段已从应用内存中清除。",
      "The mnemonic is invalid for the selected wordlist or checksum.": "助记词不属于所选词表，或校验和无效。",
      "The two passphrase entries do not match.": "两次输入的附加密码不一致。",
      "The age recipient is missing or unsupported.": "age recipient 缺失或格式不受支持。",
      "Decryption failed. Check that this private identity belongs to the selected backup.":
        "解密失败。请确认此私密 identity 与所选备份配对。",
      "A duplicate SSKR share was entered. Each share must be distinct.":
        "检测到重复的 SSKR 份额；每个份额必须互不相同。",
      "There are not enough valid SSKR shares to satisfy the recovery thresholds.":
        "有效的 SSKR 份额不足，尚未达到恢复门限。",
      "The destination already exists or is not safe to overwrite. Choose a new file.":
        "目标文件已存在或不适合覆盖，请选择新的文件名。",
      "The selected file or folder cannot be used. Check its location and permissions.":
        "无法使用所选文件或文件夹，请检查位置和访问权限。",
      "The operation could not be completed. Review the selected values and try again.":
        "操作未能完成，请检查所选内容后重试。",
      "Create encrypted backup": "创建加密备份",
      "Protect a new or existing BIP-39 seed with age encryption.":
        "使用 age 加密备份新生成或已有的 BIP-39 助记词。",
      "Inspect a backup and load its seed material securely.": "解密并检查备份，安全载入其中的助记词。",
      "Reconstruct a seed from a sufficient set of recovery shares.": "组合满足门限要求的 SSKR 份额，恢复原始种子。",
      "Derive public wallet data without exposing private keys.": "仅派生钱包的公开地址和公钥，不显示私钥。",
      "Learn how to protect and recover a wallet seed.": "了解如何安全备份、验证并恢复钱包助记词。",
      "Seed & passphrase": "助记词与附加密码", "Recovery options": "恢复方案",
      "Encryption & save": "加密与保存", "Continue to recovery": "下一步：恢复方案",
      "Continue to encryption": "下一步：加密设置", "Back to seed": "返回助记词",
      "Back to recovery": "返回恢复方案", "Generate or enter a mnemonic to continue": "请生成或输入助记词后继续",
      "Passphrase confirmation does not match": "两次输入的附加密码不一致",
      "Protect a new or existing BIP-39 mnemonic with age encryption.":
        "使用 age 加密保护新生成或已有的 BIP-39 助记词。",
      "Seed material": "助记词与附加密码",
      "Choose the mnemonic and optional BIP-39 passphrase to protect.":
        "选择要备份的助记词，并按需填写 BIP-39 附加密码。",
      "Source": "输入方式", "Language": "语言", "Generate seed": "生成助记词",
      "Randomness": "随机性来源",
      "Add mouse randomness": "加入鼠标随机性",
      "Mouse mode opens a full-screen canvas and also uses secure system randomness.":
        "鼠标模式会打开全屏采集画布，并同时使用系统安全随机源。",
      "Mouse entropy collection": "采集鼠标随机性",
      "Move your pointer unpredictably across the entire screen.":
        "请在整个屏幕上以不规则的轨迹和速度移动指针。",
      "Fortress combines these movement samples with secure operating-system randomness.":
        "Fortress 会将这些移动样本与操作系统的安全随机源混合。",
      "30-second minimum · Cover the screen · Change direction and speed":
        "至少 30 秒 · 覆盖整个屏幕 · 持续改变方向和速度",
      "Collection progress": "采集进度",
      "Keep moving—use wide, irregular paths and vary your speed.":
        "请继续移动，尽量覆盖较大范围，并不断改变轨迹和速度。",
      "Enough movement collected. You can generate the seed now.":
        "已采集足够的移动样本，现在可以生成助记词。",
      "Movement checks complete—keep moving until the timer ends.":
        "移动检查已达标，请继续移动直到计时结束。",
      "Cancel": "取消",
      "Press Esc to cancel": "按 Esc 取消",
      "Seed phrase": "助记词", "Reveal generated phrase": "显示生成的助记词",
      "Reveal seed phrase": "显示助记词", "Passphrase": "附加密码",
      "Enter the same passphrase again": "再次输入完全相同的附加密码",
      "Reveal passphrase": "显示附加密码", "Include passphrase in encrypted backup": "将附加密码写入加密备份",
      "Generate new": "新建助记词",
      "Import existing": "输入已有助记词",
      "Mnemonic wordlist": "助记词词表",
      "Word count": "词数",
      "Generate mnemonic": "生成助记词",
      "Mnemonic": "助记词",
      "Reveal words": "显示词语",
      "Hide words": "隐藏词语",
      "Validate mnemonic": "校验助记词",
      "Optional BIP-39 passphrase": "BIP-39 附加密码（可选）",
      "Confirm passphrase": "再次输入附加密码",
      "Store passphrase inside encrypted backup": "将附加密码存入加密备份",
      "Every passphrase creates a different valid wallet. Fortress can confirm matching input, but only a known address proves it is the intended wallet.":
        "任意附加密码都会生成另一个有效钱包。Fortress 只能确认两次输入一致；只有与已知地址比对，才能证明它是目标钱包。",
      "Recovery format": "备份方式",
      "Optionally replace the stored mnemonic with threshold recovery shares.":
        "可将助记词转换为具有门限保护的 SSKR 份额后再备份。",
      "Split seed into recovery shares": "改用 SSKR 恢复份额", "Create": "总数", "Require": "门限",
      "Separate storage": "分开保管", "Export each SSKR share as a separate file": "将每份 SSKR 份额导出为独立文件",
      "Export folder": "导出位置", "Choose folder": "选择文件夹",
      "Use SSKR threshold shares": "使用 SSKR 门限份额",
      "Groups": "恢复组",
      "Groups required": "所需组数",
      "Shares per group": "每组份额数",
      "Shares required per group": "每组所需份额",
      "Export individual shares to a separate folder": "将每个份额分别导出到另一文件夹",
      "Choose export folder": "选择导出文件夹",
      "No folder selected": "尚未选择文件夹",
      "Without separate export, all SSKR shares remain together inside one encrypted file; that file is still a single point of loss.":
        "若不分别导出，所有 SSKR 份额仍集中在同一个加密文件中；该文件依然是单一丢失点。",
      "Encryption": "加密",
      "Encrypt and save": "加密并保存",
      "Select who can decrypt the backup and where the encrypted file is written.":
        "指定用于加密的 age 接收公钥，并选择备份文件的保存位置。",
      "Recipient": "age 接收公钥",
      "I verified that I control this recipient's private identity": "我已确认自己持有该接收公钥对应的私钥",
      "Choose file": "选择文件", "Backup file": "备份文件",
      "Need a key? Create a private age identity locally; its public recipient will be filled in automatically.":
        "还没有密钥？可在本机创建 age 私钥，应用会自动填入对应的接收公钥。",
      "Create age identity": "创建 age 私钥", "Unlock backup": "解密备份",
      "Choose the encrypted file and supply a matching private age identity.":
        "选择加密备份，并提供与接收公钥匹配的 age 解密私钥。",
      "Open file": "打开文件", "Private identity": "age 解密私钥", "Reveal identity": "显示解密私钥",
      "Decrypted contents": "备份内容",
      "Sensitive values remain masked until you explicitly reveal them.": "敏感值将保持隐藏，直到你明确选择显示。",
      "Reveal sensitive values": "显示敏感值", "Open address derivation": "打开地址派生",
      "Recovery shares": "SSKR 恢复份额",
      "Paste one unique hexadecimal or mnemonic SSKR share per line.":
        "每行粘贴一份且不要重复；支持十六进制或助记词形式的 SSKR 份额。",
      "Share language": "份额语言", "Wallet passphrase": "BIP-39 附加密码",
      "Enter the original BIP-39 passphrase if this wallet used one.":
        "如果创建钱包时使用了 BIP-39 附加密码，请在此输入完全相同的内容。",
      "Recover seed": "恢复种子", "Derivation inputs": "钱包信息",
      "Use a loaded backup or paste a valid BIP-39 mnemonic manually.":
        "使用已载入的备份，或手动粘贴有效的 BIP-39 助记词。",
      "Address type": "地址类型", "Index range": "索引范围", "Start": "开始", "End": "结束",
      "Public results": "派生结果",
      "Addresses and public keys are safe to share; no private keys are displayed.":
        "这些地址和公钥可以安全分享；不会显示任何私钥。",
      "age recipient": "age recipient",
      "Paste an age1… recipient or choose a recipient file": "粘贴 age1… recipient，或选择 recipient 文件",
      "Choose recipient file": "选择 recipient 文件",
      "Create identity…": "创建 identity…",
      "I control the matching private identity": "我掌握配对的私密 identity",
      "Save encrypted backup…": "保存加密备份…",
      "Open encrypted backup": "打开加密备份",
      "Decrypt a Fortress backup with its private age identity, then inspect and verify the recovered seed.":
        "使用私密 age identity 解密 Fortress 备份，然后核对并验证恢复的助记词。",
      "Encrypted backup file": "加密备份文件",
      "Choose backup…": "选择备份…",
      "Private age identity": "私密 age identity",
      "Paste AGE-SECRET-KEY-… or choose an identity file": "粘贴 AGE-SECRET-KEY-…，或选择 identity 文件",
      "Choose identity file": "选择 identity 文件",
      "Decrypt backup": "解密备份",
      "Recovered seed": "恢复的助记词",
      "Passphrase was stored in this backup.": "此备份包含附加密码。",
      "No passphrase was stored. Enter the original one before deriving if the wallet used one.":
        "备份中没有附加密码。若原钱包使用过附加密码，请在派生地址前输入原内容。",
      "SSKR groups reconstructed automatically": "已自动组合 SSKR 组",
      "Load into Addresses": "载入地址派生",
      "Recover from SSKR shares": "从 SSKR 份额恢复",
      "Paste enough distinct shares to satisfy both the group and per-group thresholds.":
        "粘贴足够且互不重复的份额，同时满足组门限和组内份额门限。",
      "Share wordlist": "份额词表",
      "One mnemonic or hexadecimal share per line": "每行一个助记词份额或十六进制份额",
      "SSKR shares": "SSKR 份额",
      "Reconstruct seed": "重组助记词",
      "Passphrase for address verification (optional)": "用于地址验证的附加密码（可选）",
      "Address derivation": "派生地址",
      "Derive public wallet data and compare it with an address you already trust.":
        "派生公开钱包资料，并与已知可信地址比对。",
      "Network": "网络",
      "Start index": "起始索引",
      "End index": "结束索引",
      "Harden final index": "末级索引使用硬化派生",
      "Derive addresses": "派生地址",
      "Index": "索引",
      "Path": "路径",
      "Address": "地址",
      "Public key": "公钥",
      "No private keys are displayed or returned by the Rust core.": "Rust 核心不会显示或返回任何私钥。",
      "Help & safety guide": "帮助与安全指南",
      "Learn how to protect and recover a wallet seed before storing real funds.":
        "在存入真实资产前，先了解如何保护并恢复钱包助记词。",
      "Read this before storing real funds": "存入真实资产前请先阅读",
      "A backup is useful only after you have decrypted it, reconstructed its seed material, and matched a known wallet address.":
        "只有亲自完成解密、重组助记词并匹配已知钱包地址后，这份备份才算真正可用。",
      "English": "英语",
      "Simplified Chinese": "简体中文",
      "Traditional Chinese": "繁体中文",
      "Japanese": "日语",
      "Korean": "韩语",
      "Spanish": "西班牙语",
      "French": "法语",
      "Italian": "意大利语",
      "Czech": "捷克语",
      "Portuguese": "葡萄牙语",
    ],
    .japanese: [
      "Create backup": "バックアップ作成",
      "Open backup": "バックアップを開く",
      "Recover SSKR": "SSKR を復元",
      "Addresses": "アドレス導出",
      "Help": "使い方",
      "Encrypt seed material": "ニーモニックを暗号化",
      "Decrypt and inspect": "復号して内容を確認",
      "Combine recovery shares": "SSKR シェアを結合",
      "Derive public keys": "公開アドレスを生成",
      "Start here": "まずはこちら",
      "Clear sensitive data": "機密情報を消去",
      "Secrets remain in this app's memory only while needed": "機密情報は必要な間だけアプリのメモリ内に保持されます",
      "Checking age…": "age を確認中…",
      "Checking bundled age…": "同梱 age を確認中…",
      "Verified age update": "検証済み age 更新",
      "Bundled age verified": "同梱 age を検証済み",
      "Bundled age available": "同梱 age を使用可能",
      "A new mnemonic was generated locally.": "新しいニーモニックをこの端末内で生成しました。",
      "Generated a new seed using operating-system and mouse randomness.":
        "OS の安全な乱数とマウス操作の乱数性から、新しいニーモニックを生成しました。",
      "Mnemonic checksum is valid": "単語リストとチェックサムを確認済み",
      "words · checksum valid": "語・チェックサム有効",
      "Invalid mnemonic or checksum": "ニーモニックまたはチェックサムが無効です",
      "The mnemonic is valid for the selected language.": "選択した単語リストのニーモニックとして有効です。",
      "Private identity saved. Keep it separate from the backup.":
        "秘密 identity を保存しました。暗号化バックアップとは別に保管してください。",
      "Confirm that you control the matching private identity.":
        "recipient に対応する秘密 identity を管理していることを確認してください。",
      "Passphrase entries do not match.": "パスフレーズが一致しません。",
      "Encrypted backup saved": "暗号化バックアップを保存しました",
      "SSKR shares exported": "SSKR シェアを書き出しました",
      "Backup decrypted and SSKR seed reconstructed.": "バックアップを復号し、SSKR からニーモニックを再構成しました。",
      "Backup decrypted and mnemonic validated.": "バックアップを復号し、ニーモニックを検証しました。",
      "Backup type": "バックアップ形式",
      "Mnemonic language": "ニーモニック言語",
      "Recovery rule": "復元しきい値",
      "Schema version": "形式バージョン",
      "Direct mnemonic backup": "ニーモニック直接バックアップ",
      "SSKR threshold backup": "SSKR しきい値バックアップ",
      "Recovered seed and stored passphrase loaded into Addresses.":
        "復元したニーモニックと保存済みパスフレーズをアドレス導出へ読み込みました。",
      "Recovered seed loaded. Enter the original passphrase if one was used.":
        "ニーモニックを読み込みました。元のウォレットで使用していた場合は、同じパスフレーズを入力してください。",
      "SSKR seed reconstructed and validated.": "SSKR からニーモニックを再構成し、検証しました。",
      "Recovered seed loaded into Addresses.": "復元したニーモニックをアドレス導出へ読み込みました。",
      "public addresses derived.": "件の公開アドレスを導出しました。",
      "Sensitive fields were cleared from application memory.": "機密フィールドをアプリのメモリから消去しました。",
      "The mnemonic is invalid for the selected wordlist or checksum.":
        "選択した単語リストにない語があるか、チェックサムが無効です。",
      "The two passphrase entries do not match.": "2 回入力したパスフレーズが一致しません。",
      "The age recipient is missing or unsupported.": "age recipient が未入力か、対応していない形式です。",
      "Decryption failed. Check that this private identity belongs to the selected backup.":
        "復号できませんでした。この秘密 identity が選択したバックアップに対応しているか確認してください。",
      "A duplicate SSKR share was entered. Each share must be distinct.":
        "同じ SSKR シェアが重複しています。異なるシェアを入力してください。",
      "There are not enough valid SSKR shares to satisfy the recovery thresholds.":
        "有効な SSKR シェアが不足しており、復元しきい値を満たしていません。",
      "The destination already exists or is not safe to overwrite. Choose a new file.":
        "保存先が既に存在するか、安全に上書きできません。新しいファイル名を選んでください。",
      "The selected file or folder cannot be used. Check its location and permissions.":
        "選択したファイルまたはフォルダを使用できません。場所とアクセス権を確認してください。",
      "The operation could not be completed. Review the selected values and try again.":
        "操作を完了できませんでした。入力内容を確認して、もう一度お試しください。",
      "Create encrypted backup": "暗号化バックアップを作成",
      "Protect a new or existing BIP-39 seed with age encryption.":
        "新規または既存の BIP-39 ニーモニックを age で暗号化して保存します。",
      "Inspect a backup and load its seed material securely.":
        "バックアップを復号して内容を確認し、ニーモニックを安全に読み込みます。",
      "Reconstruct a seed from a sufficient set of recovery shares.":
        "しきい値を満たす SSKR シェアを組み合わせて元のシードを復元します。",
      "Derive public wallet data without exposing private keys.":
        "秘密鍵を表示せず、ウォレットの公開アドレスと公開鍵だけを導出します。",
      "Learn how to protect and recover a wallet seed.": "ウォレットのシードを安全に保護し、復元する方法を説明します。",
      "Seed & passphrase": "ニーモニックとパスフレーズ", "Recovery options": "復元オプション",
      "Encryption & save": "暗号化と保存", "Continue to recovery": "次へ：復元オプション",
      "Continue to encryption": "次へ：暗号化設定", "Back to seed": "ニーモニックに戻る",
      "Back to recovery": "復元オプションに戻る",
      "Generate or enter a mnemonic to continue": "ニーモニックを生成または入力してください",
      "Passphrase confirmation does not match": "パスフレーズが一致していません",
      "Protect a new or existing BIP-39 mnemonic with age encryption.":
        "新規または既存の BIP-39 ニーモニックを age で暗号化します。",
      "Seed material": "ニーモニックとパスフレーズ",
      "Choose the mnemonic and optional BIP-39 passphrase to protect.":
        "保護するニーモニックと任意の BIP-39 パスフレーズを選択します。",
      "Source": "入力方法", "Language": "言語", "Generate seed": "ニーモニックを生成",
      "Randomness": "乱数の生成方法",
      "Add mouse randomness": "マウス操作の乱数性を加える",
      "Mouse mode opens a full-screen canvas and also uses secure system randomness.":
        "マウスモードでは全画面の収集画面が開き、OS の安全な乱数も併用されます。",
      "Mouse entropy collection": "マウス操作から乱数性を収集",
      "Move your pointer unpredictably across the entire screen.":
        "画面全体で、軌跡と速さを不規則に変えながらポインターを動かしてください。",
      "Fortress combines these movement samples with secure operating-system randomness.":
        "Fortress は移動サンプルと OS が提供する安全な乱数を混ぜ合わせます。",
      "30-second minimum · Cover the screen · Change direction and speed":
        "最低 30 秒 · 画面全体を使う · 方向と速さを変える",
      "Collection progress": "収集状況",
      "Keep moving—use wide, irregular paths and vary your speed.":
        "広い範囲を使い、軌跡と速さを変えながら動かし続けてください。",
      "Enough movement collected. You can generate the seed now.":
        "十分な移動サンプルを収集しました。ニーモニックを生成できます。",
      "Movement checks complete—keep moving until the timer ends.":
        "移動条件を満たしました。タイマーが終わるまで動かし続けてください。",
      "Cancel": "キャンセル",
      "Press Esc to cancel": "Esc キーでキャンセル",
      "Seed phrase": "ニーモニック", "Reveal generated phrase": "生成したニーモニックを表示",
      "Reveal seed phrase": "ニーモニックを表示", "Passphrase": "パスフレーズ",
      "Enter the same passphrase again": "同じパスフレーズをもう一度入力",
      "Reveal passphrase": "パスフレーズを表示", "Include passphrase in encrypted backup": "暗号化バックアップに含める",
      "Generate new": "新しく作成",
      "Import existing": "既存のニーモニックを入力",
      "Mnemonic wordlist": "単語リスト",
      "Word count": "語数",
      "Generate mnemonic": "ニーモニックを生成",
      "Mnemonic": "ニーモニック",
      "Reveal words": "単語を表示",
      "Hide words": "単語を隠す",
      "Validate mnemonic": "ニーモニックを検証",
      "Optional BIP-39 passphrase": "任意の BIP-39 パスフレーズ",
      "Confirm passphrase": "パスフレーズを再入力",
      "Store passphrase inside encrypted backup": "パスフレーズを暗号化バックアップ内に保存",
      "Every passphrase creates a different valid wallet. Fortress can confirm matching input, but only a known address proves it is the intended wallet.":
        "パスフレーズが異なると、すべて別の有効なウォレットになります。Fortress が確認できるのは入力の一致だけで、目的のウォレットかどうかは既知アドレスとの照合が必要です。",
      "Recovery format": "バックアップ方式",
      "Optionally replace the stored mnemonic with threshold recovery shares.":
        "ニーモニックを、しきい値付きの SSKR シェアに変換して保存できます。",
      "Split seed into recovery shares": "SSKR リカバリーシェアを使用", "Create": "総数", "Require": "しきい値",
      "Separate storage": "分散保管",
      "Export each SSKR share as a separate file": "各 SSKR シェアを個別ファイルに書き出す",
      "Export folder": "書き出し先", "Choose folder": "フォルダーを選択",
      "Use SSKR threshold shares": "SSKR しきい値シェアを使用",
      "Groups": "リカバリーグループ",
      "Groups required": "必要グループ数",
      "Shares per group": "グループ内のシェア数",
      "Shares required per group": "各グループの必要シェア数",
      "Export individual shares to a separate folder": "各シェアを別フォルダへ個別に書き出す",
      "Choose export folder": "書き出し先を選択",
      "No folder selected": "フォルダ未選択",
      "Without separate export, all SSKR shares remain together inside one encrypted file; that file is still a single point of loss.":
        "個別に書き出さない場合、すべての SSKR シェアが 1 個の暗号化ファイル内に残るため、そのファイル自体が単一障害点になります。",
      "Encryption": "暗号化",
      "Encrypt and save": "暗号化して保存",
      "Select who can decrypt the backup and where the encrypted file is written.":
        "暗号化先となる age 受信者公開鍵と、バックアップの保存先を指定します。",
      "Recipient": "age 受信者公開鍵",
      "I verified that I control this recipient's private identity":
        "この受信者公開鍵に対応する秘密鍵を保有していることを確認しました",
      "Choose file": "ファイルを選択", "Backup file": "バックアップファイル",
      "Need a key? Create a private age identity locally; its public recipient will be filled in automatically.":
        "鍵がない場合は、この端末で age 秘密鍵を作成できます。対応する受信者公開鍵は自動入力されます。",
      "Create age identity": "age 秘密鍵を作成", "Unlock backup": "バックアップを復号",
      "Choose the encrypted file and supply a matching private age identity.":
        "暗号化バックアップと、それに対応する age 秘密鍵を指定します。",
      "Open file": "ファイルを開く", "Private identity": "age 秘密鍵", "Reveal identity": "秘密鍵を表示",
      "Decrypted contents": "バックアップの内容",
      "Sensitive values remain masked until you explicitly reveal them.": "機密値は明示的に表示するまでマスクされます。",
      "Reveal sensitive values": "機密値を表示", "Open address derivation": "アドレス導出を開く",
      "Recovery shares": "SSKR リカバリーシェア",
      "Paste one unique hexadecimal or mnemonic SSKR share per line.":
        "重複しない SSKR シェアを 1 行に 1 つ貼り付けます。16 進数形式とニーモニック形式に対応しています。",
      "Share language": "シェアの言語", "Wallet passphrase": "BIP-39 パスフレーズ",
      "Enter the original BIP-39 passphrase if this wallet used one.":
        "このウォレットで使用した元の BIP-39 パスフレーズを入力します。",
      "Recover seed": "シードを復元", "Derivation inputs": "ウォレット情報",
      "Use a loaded backup or paste a valid BIP-39 mnemonic manually.":
        "読み込んだバックアップを使うか、有効な BIP-39 ニーモニックを貼り付けます。",
      "Address type": "アドレス種別", "Index range": "インデックス範囲", "Start": "開始", "End": "終了",
      "Public results": "導出結果",
      "Addresses and public keys are safe to share; no private keys are displayed.":
        "アドレスと公開鍵は共有できます。秘密鍵は表示されません。",
      "age recipient": "age recipient",
      "Paste an age1… recipient or choose a recipient file":
        "age1… recipient を貼り付けるか、recipient ファイルを選択",
      "Choose recipient file": "recipient ファイルを選択",
      "Create identity…": "identity を作成…",
      "I control the matching private identity": "対応する秘密 identity を自分で管理しています",
      "Save encrypted backup…": "暗号化バックアップを保存…",
      "Open encrypted backup": "暗号化バックアップを開く",
      "Decrypt a Fortress backup with its private age identity, then inspect and verify the recovered seed.":
        "秘密 age identity で Fortress バックアップを復号し、復元したニーモニックを確認します。",
      "Encrypted backup file": "暗号化バックアップファイル",
      "Choose backup…": "バックアップを選択…",
      "Private age identity": "秘密 age identity",
      "Paste AGE-SECRET-KEY-… or choose an identity file":
        "AGE-SECRET-KEY-… を貼り付けるか、identity ファイルを選択",
      "Choose identity file": "identity ファイルを選択",
      "Decrypt backup": "バックアップを復号",
      "Recovered seed": "復元したニーモニック",
      "Passphrase was stored in this backup.": "このバックアップにはパスフレーズが保存されています。",
      "No passphrase was stored. Enter the original one before deriving if the wallet used one.":
        "パスフレーズは保存されていません。元のウォレットで使用していた場合は、導出前に同じ内容を入力してください。",
      "SSKR groups reconstructed automatically": "SSKR グループを自動的に再構成しました",
      "Load into Addresses": "アドレス導出へ読み込む",
      "Recover from SSKR shares": "SSKR シェアから復元",
      "Paste enough distinct shares to satisfy both the group and per-group thresholds.":
        "グループしきい値とグループ内しきい値の両方を満たす、重複しないシェアを入力してください。",
      "Share wordlist": "シェアの単語リスト",
      "One mnemonic or hexadecimal share per line": "1 行につきニーモニックまたは 16 進数のシェアを 1 つ",
      "SSKR shares": "SSKR シェア",
      "Reconstruct seed": "ニーモニックを再構成",
      "Passphrase for address verification (optional)": "アドレス確認用パスフレーズ（任意）",
      "Address derivation": "アドレス導出",
      "Derive public wallet data and compare it with an address you already trust.":
        "公開ウォレット情報を導出し、信頼済みのアドレスと照合します。",
      "Network": "ネットワーク",
      "Start index": "開始インデックス",
      "End index": "終了インデックス",
      "Harden final index": "末尾のインデックスを hardened にする",
      "Derive addresses": "アドレスを導出",
      "Index": "インデックス",
      "Path": "パス",
      "Address": "アドレス",
      "Public key": "公開鍵",
      "No private keys are displayed or returned by the Rust core.":
        "Rust コアは秘密鍵を表示せず、Swift 側にも返しません。",
      "Help & safety guide": "ヘルプと安全ガイド",
      "Learn how to protect and recover a wallet seed before storing real funds.":
        "実際の資産を入れる前に、ニーモニックを安全に保護・復元する方法を確認してください。",
      "Read this before storing real funds": "実際の資産を入れる前にお読みください",
      "A backup is useful only after you have decrypted it, reconstructed its seed material, and matched a known wallet address.":
        "復号、ニーモニックの再構成、既知アドレスとの一致まで確認して初めて、バックアップは実用可能といえます。",
      "English": "英語", "Simplified Chinese": "簡体字中国語", "Traditional Chinese": "繁体字中国語",
      "Japanese": "日本語", "Korean": "韓国語", "Spanish": "スペイン語", "French": "フランス語", "Italian": "イタリア語",
      "Czech": "チェコ語", "Portuguese": "ポルトガル語",
    ],
    .korean: [
      "Create backup": "백업 만들기",
      "Open backup": "백업 열기",
      "Recover SSKR": "SSKR 복구",
      "Addresses": "주소 파생",
      "Help": "도움말",
      "Encrypt seed material": "니모닉 백업 암호화",
      "Decrypt and inspect": "복호화 후 내용 확인",
      "Combine recovery shares": "SSKR 조각 조합",
      "Derive public keys": "공개 주소 생성",
      "Start here": "처음 시작하기",
      "Clear sensitive data": "민감한 정보 지우기",
      "Secrets remain in this app's memory only while needed": "민감한 정보는 필요한 동안만 앱 메모리에 유지됩니다",
      "Checking age…": "age 확인 중…", "Checking bundled age…": "내장 age 확인 중…",
      "Verified age update": "검증된 age 업데이트", "Bundled age verified": "내장 age 검증 완료",
      "Bundled age available": "내장 age 사용 가능",
      "A new mnemonic was generated locally.": "새 니모닉을 이 기기에서 생성했습니다.",
      "Generated a new seed using operating-system and mouse randomness.":
        "운영체제의 안전한 난수와 마우스 무작위성을 사용해 새로운 니모닉을 생성했습니다.",
      "Mnemonic checksum is valid": "단어 목록과 체크섬이 유효합니다", "words · checksum valid": "단어 · 체크섬 유효",
      "Invalid mnemonic or checksum": "니모닉 또는 체크섬이 잘못되었습니다",
      "The mnemonic is valid for the selected language.": "선택한 단어 목록에 맞고 체크섬도 유효합니다.",
      "Private identity saved. Keep it separate from the backup.":
        "비공개 identity를 저장했습니다. 암호화 백업과 분리해 보관하세요.",
      "Confirm that you control the matching private identity.":
        "recipient와 짝을 이루는 비공개 identity를 직접 관리하는지 확인하세요.",
      "Passphrase entries do not match.": "패스프레이즈 입력이 서로 다릅니다.",
      "Encrypted backup saved": "암호화 백업 저장 완료", "SSKR shares exported": "SSKR 조각 내보내기 완료",
      "Backup decrypted and SSKR seed reconstructed.": "백업을 복호화하고 SSKR 니모닉을 재구성했습니다.",
      "Backup decrypted and mnemonic validated.": "백업을 복호화하고 니모닉을 검증했습니다.",
      "Backup type": "백업 형식", "Mnemonic language": "니모닉 언어", "Recovery rule": "복구 임계값",
      "Schema version": "형식 버전", "Direct mnemonic backup": "니모닉 직접 백업",
      "SSKR threshold backup": "SSKR 임계값 백업",
      "Recovered seed and stored passphrase loaded into Addresses.":
        "복구한 니모닉과 저장된 패스프레이즈를 주소 파생으로 불러왔습니다.",
      "Recovered seed loaded. Enter the original passphrase if one was used.":
        "니모닉을 불러왔습니다. 원래 지갑에서 사용했다면 동일한 패스프레이즈를 입력하세요.",
      "SSKR seed reconstructed and validated.": "SSKR 니모닉을 재구성하고 검증했습니다.",
      "Recovered seed loaded into Addresses.": "복구한 니모닉을 주소 파생으로 불러왔습니다.",
      "public addresses derived.": "개의 공개 주소를 파생했습니다.",
      "Sensitive fields were cleared from application memory.": "민감한 필드를 앱 메모리에서 지웠습니다.",
      "The mnemonic is invalid for the selected wordlist or checksum.":
        "선택한 단어 목록에 없는 단어가 있거나 체크섬이 잘못되었습니다.",
      "The two passphrase entries do not match.": "두 패스프레이즈 입력이 서로 다릅니다.",
      "The age recipient is missing or unsupported.": "age recipient가 없거나 지원하지 않는 형식입니다.",
      "Decryption failed. Check that this private identity belongs to the selected backup.":
        "복호화하지 못했습니다. 이 비공개 identity가 선택한 백업과 짝을 이루는지 확인하세요.",
      "A duplicate SSKR share was entered. Each share must be distinct.":
        "중복된 SSKR 조각이 있습니다. 서로 다른 조각을 입력하세요.",
      "There are not enough valid SSKR shares to satisfy the recovery thresholds.":
        "유효한 SSKR 조각이 부족하여 복구 임계값을 충족하지 못했습니다.",
      "The destination already exists or is not safe to overwrite. Choose a new file.":
        "대상 파일이 이미 있거나 안전하게 덮어쓸 수 없습니다. 새 파일 이름을 선택하세요.",
      "The selected file or folder cannot be used. Check its location and permissions.":
        "선택한 파일이나 폴더를 사용할 수 없습니다. 위치와 권한을 확인하세요.",
      "The operation could not be completed. Review the selected values and try again.":
        "작업을 완료하지 못했습니다. 선택한 값을 확인한 뒤 다시 시도하세요.",
      "Create encrypted backup": "암호화 백업 만들기",
      "Protect a new or existing BIP-39 seed with age encryption.":
        "새로 만들거나 기존에 사용하던 BIP-39 니모닉을 age로 암호화해 백업합니다.",
      "Inspect a backup and load its seed material securely.": "백업을 복호화해 내용을 확인하고 니모닉을 안전하게 불러옵니다.",
      "Reconstruct a seed from a sufficient set of recovery shares.":
        "임계값을 충족하는 SSKR 조각을 조합해 원래 시드를 복구합니다.",
      "Derive public wallet data without exposing private keys.":
        "개인 키를 표시하지 않고 공개 주소와 공개 키만 파생합니다.",
      "Learn how to protect and recover a wallet seed.": "지갑 시드를 안전하게 백업하고 복구하는 방법을 알아보세요.",
      "Seed & passphrase": "니모닉 및 패스프레이즈", "Recovery options": "복구 옵션",
      "Encryption & save": "암호화 및 저장", "Continue to recovery": "다음: 복구 옵션",
      "Continue to encryption": "다음: 암호화 설정", "Back to seed": "니모닉으로 돌아가기",
      "Back to recovery": "복구 옵션으로 돌아가기",
      "Generate or enter a mnemonic to continue": "니모닉을 생성하거나 입력하세요",
      "Passphrase confirmation does not match": "패스프레이즈가 일치하지 않습니다",
      "Protect a new or existing BIP-39 mnemonic with age encryption.":
        "새 BIP-39 니모닉이나 기존 니모닉을 age로 암호화합니다.", "Seed material": "니모닉 및 패스프레이즈",
      "Generate new": "새로 생성",
      "Choose the mnemonic and optional BIP-39 passphrase to protect.":
        "백업할 니모닉을 선택하고 필요한 경우 BIP-39 패스프레이즈를 입력하세요.",
      "Source": "입력 방식", "Language": "언어", "Generate seed": "니모닉 생성",
      "Randomness": "무작위성 방식",
      "Add mouse randomness": "마우스 무작위성 추가",
      "Mouse mode opens a full-screen canvas and also uses secure system randomness.":
        "마우스 모드는 전체 화면 수집 창을 열고 운영체제의 안전한 난수도 함께 사용합니다.",
      "Mouse entropy collection": "마우스 무작위성 수집",
      "Move your pointer unpredictably across the entire screen.":
        "화면 전체에서 경로와 속도를 불규칙하게 바꾸며 포인터를 움직이세요.",
      "Fortress combines these movement samples with secure operating-system randomness.":
        "Fortress는 이동 샘플과 운영체제가 제공하는 안전한 난수를 혼합합니다.",
      "30-second minimum · Cover the screen · Change direction and speed":
        "최소 30초 · 화면 전체 사용 · 방향과 속도 바꾸기",
      "Collection progress": "수집 진행률",
      "Keep moving—use wide, irregular paths and vary your speed.":
        "넓은 영역을 사용하고 경로와 속도를 바꾸면서 계속 움직이세요.",
      "Enough movement collected. You can generate the seed now.":
        "충분한 이동 샘플을 수집했습니다. 이제 니모닉을 생성할 수 있습니다.",
      "Movement checks complete—keep moving until the timer ends.":
        "이동 조건을 충족했습니다. 타이머가 끝날 때까지 계속 움직이세요.",
      "Cancel": "취소",
      "Press Esc to cancel": "Esc 키를 누르면 취소됩니다",
      "Seed phrase": "니모닉",
      "Reveal generated phrase": "생성된 니모닉 표시", "Reveal seed phrase": "니모닉 표시",
      "Passphrase": "패스프레이즈",
      "Enter the same passphrase again": "같은 패스프레이즈를 다시 입력", "Reveal passphrase": "패스프레이즈 표시",
      "Include passphrase in encrypted backup": "암호화 백업에 패스프레이즈 포함",
      "Import existing": "기존 니모닉 입력", "Mnemonic wordlist": "니모닉 단어 목록", "Word count": "단어 수",
      "Generate mnemonic": "니모닉 생성", "Mnemonic": "니모닉", "Reveal words": "단어 표시",
      "Hide words": "단어 숨기기", "Validate mnemonic": "니모닉 검증",
      "Optional BIP-39 passphrase": "BIP-39 패스프레이즈(선택 사항)", "Confirm passphrase": "패스프레이즈 확인",
      "Store passphrase inside encrypted backup": "암호화 백업 안에 패스프레이즈 저장",
      "Every passphrase creates a different valid wallet. Fortress can confirm matching input, but only a known address proves it is the intended wallet.":
        "패스프레이즈가 달라지면 모두 별개의 유효한 지갑이 됩니다. Fortress는 두 입력이 같은지만 확인하며, 의도한 지갑인지는 이미 아는 주소와 비교해야 합니다.",
      "Recovery format": "백업 방식", "Use SSKR threshold shares": "SSKR 임계값 조각 사용", "Groups": "복구 그룹",
      "Optionally replace the stored mnemonic with threshold recovery shares.":
        "니모닉을 임계값 방식의 SSKR 복구 조각으로 변환해 저장할 수 있습니다.",
      "Split seed into recovery shares": "SSKR 복구 조각 사용", "Create": "전체", "Require": "임계값",
      "Separate storage": "분리 보관",
      "Export each SSKR share as a separate file": "각 SSKR 조각을 별도 파일로 내보내기",
      "Export folder": "내보낼 폴더", "Choose folder": "폴더 선택",
      "Groups required": "필요 그룹 수", "Shares per group": "그룹당 조각 수",
      "Shares required per group": "그룹당 필요 조각 수",
      "Export individual shares to a separate folder": "각 조각을 별도 폴더로 내보내기",
      "Choose export folder": "내보낼 폴더 선택", "No folder selected": "선택한 폴더 없음",
      "Without separate export, all SSKR shares remain together inside one encrypted file; that file is still a single point of loss.":
        "별도로 내보내지 않으면 모든 SSKR 조각이 암호화 파일 하나에 함께 남으므로 그 파일이 여전히 단일 손실 지점입니다.",
      "Encryption": "암호화", "age recipient": "age recipient",
      "Encrypt and save": "암호화 및 저장",
      "Select who can decrypt the backup and where the encrypted file is written.":
        "암호화에 사용할 age 수신자 공개 키와 백업 파일의 저장 위치를 지정하세요.",
      "Recipient": "age 수신자 공개 키",
      "I verified that I control this recipient's private identity":
        "이 수신자 공개 키에 해당하는 개인 키를 보유하고 있음을 확인했습니다",
      "Choose file": "파일 선택", "Backup file": "백업 파일",
      "Need a key? Create a private age identity locally; its public recipient will be filled in automatically.":
        "키가 없다면 이 기기에서 age 개인 키를 만들 수 있습니다. 해당 수신자 공개 키는 자동으로 입력됩니다.",
      "Create age identity": "age 개인 키 만들기", "Unlock backup": "백업 복호화",
      "Choose the encrypted file and supply a matching private age identity.":
        "암호화된 백업과 수신자 공개 키에 대응하는 age 개인 키를 지정하세요.",
      "Open file": "파일 열기", "Private identity": "age 개인 키", "Reveal identity": "개인 키 표시",
      "Decrypted contents": "백업 내용",
      "Sensitive values remain masked until you explicitly reveal them.":
        "민감한 값은 명시적으로 표시할 때까지 가려집니다.",
      "Reveal sensitive values": "민감한 값 표시", "Open address derivation": "주소 파생 열기",
      "Recovery shares": "SSKR 복구 조각",
      "Paste one unique hexadecimal or mnemonic SSKR share per line.":
        "중복되지 않은 SSKR 조각을 한 줄에 하나씩 붙여 넣으세요. 16진수 및 니모닉 형식을 지원합니다.",
      "Share language": "조각 언어", "Wallet passphrase": "BIP-39 패스프레이즈",
      "Enter the original BIP-39 passphrase if this wallet used one.":
        "지갑을 만들 때 사용한 BIP-39 패스프레이즈를 정확히 입력하세요.",
      "Recover seed": "시드 복구", "Derivation inputs": "지갑 정보",
      "Use a loaded backup or paste a valid BIP-39 mnemonic manually.":
        "불러온 백업을 사용하거나 유효한 BIP-39 니모닉을 직접 붙여 넣으세요.",
      "Address type": "주소 유형", "Index range": "인덱스 범위", "Start": "시작", "End": "끝",
      "Public results": "파생 결과",
      "Addresses and public keys are safe to share; no private keys are displayed.":
        "주소와 공개 키는 공유해도 안전하며 개인 키는 표시되지 않습니다.",
      "Paste an age1… recipient or choose a recipient file":
        "age1… recipient를 붙여 넣거나 recipient 파일 선택", "Choose recipient file": "recipient 파일 선택",
      "Create identity…": "identity 만들기…",
      "I control the matching private identity": "짝이 되는 비공개 identity를 직접 관리합니다",
      "Save encrypted backup…": "암호화 백업 저장…",
      "Open encrypted backup": "암호화 백업 열기",
      "Decrypt a Fortress backup with its private age identity, then inspect and verify the recovered seed.":
        "비공개 age identity로 Fortress 백업을 복호화한 뒤 복구된 니모닉을 확인합니다.",
      "Encrypted backup file": "암호화 백업 파일", "Choose backup…": "백업 선택…",
      "Private age identity": "비공개 age identity",
      "Paste AGE-SECRET-KEY-… or choose an identity file":
        "AGE-SECRET-KEY-…를 붙여 넣거나 identity 파일 선택", "Choose identity file": "identity 파일 선택",
      "Decrypt backup": "백업 복호화", "Recovered seed": "복구된 니모닉",
      "Passphrase was stored in this backup.": "이 백업에는 패스프레이즈가 저장되어 있습니다.",
      "No passphrase was stored. Enter the original one before deriving if the wallet used one.":
        "패스프레이즈가 저장되지 않았습니다. 원래 지갑에서 사용했다면 주소 파생 전에 동일하게 입력하세요.",
      "SSKR groups reconstructed automatically": "SSKR 그룹 자동 재구성 완료",
      "Load into Addresses": "주소 파생으로 불러오기",
      "Recover from SSKR shares": "SSKR 조각으로 복구",
      "Paste enough distinct shares to satisfy both the group and per-group thresholds.":
        "그룹 임계값과 그룹 내 임계값을 모두 충족하도록 서로 다른 조각을 충분히 입력하세요.", "Share wordlist": "조각 단어 목록",
      "One mnemonic or hexadecimal share per line": "한 줄에 니모닉 또는 16진수 조각 하나",
      "SSKR shares": "SSKR 조각", "Reconstruct seed": "니모닉 재구성",
      "Passphrase for address verification (optional)": "주소 확인용 패스프레이즈(선택)",
      "Address derivation": "주소 파생",
      "Derive public wallet data and compare it with an address you already trust.":
        "공개 지갑 정보를 파생하여 이미 신뢰하는 주소와 비교합니다.", "Network": "네트워크", "Start index": "시작 인덱스",
      "End index": "끝 인덱스", "Harden final index": "마지막 인덱스 하드닝", "Derive addresses": "주소 파생",
      "Index": "인덱스", "Path": "경로", "Address": "주소", "Public key": "공개 키",
      "No private keys are displayed or returned by the Rust core.":
        "Rust 코어는 개인 키를 표시하거나 Swift 화면으로 반환하지 않습니다.",
      "Help & safety guide": "도움말 및 안전 가이드",
      "Learn how to protect and recover a wallet seed before storing real funds.":
        "실제 자산을 보관하기 전에 니모닉을 안전하게 보호하고 복구하는 방법을 확인하세요.",
      "Read this before storing real funds": "실제 자산을 넣기 전에 읽어보세요",
      "A backup is useful only after you have decrypted it, reconstructed its seed material, and matched a known wallet address.":
        "직접 복호화하고 니모닉을 재구성한 뒤 알고 있는 지갑 주소와 일치하는지 확인해야 백업이 실제로 쓸 수 있는 상태입니다.",
      "English": "영어", "Simplified Chinese": "중국어 간체", "Traditional Chinese": "중국어 번체",
      "Japanese": "일본어", "Korean": "한국어", "Spanish": "스페인어", "French": "프랑스어", "Italian": "이탈리아어",
      "Czech": "체코어", "Portuguese": "포르투갈어",
    ],
  ]
}

struct HelpTopic: Identifiable {
  let id: String
  let symbol: String
  let title: String
  let introduction: String
  let bullets: [String]
  let exampleTitle: String
  let example: String
}

extension AppLanguage {
  var helpTopics: [HelpTopic] {
    switch self {
    case .english:
      return Self.englishHelp
    case .simplifiedChinese:
      return Self.chineseHelp
    case .japanese:
      return Self.japaneseHelp
    case .korean:
      return Self.koreanHelp
    }
  }

  private static let englishHelp = [
    HelpTopic(
      id: "purpose", symbol: "shield.lefthalf.filled", title: "What Fortress does",
      introduction:
        "Fortress is an offline backup and verification tool for wallet recovery material. It is not a wallet and it never sends transactions, connects to a blockchain, tracks balances, or holds coins.",
      bullets: [
        "It validates and encrypts a BIP-39 mnemonic or SSKR shares into an age file.",
        "It opens that file later and derives public addresses for verification without returning derived private keys to Swift.",
        "Encryption protects confidentiality; separate copies and recovery drills protect availability.",
      ], exampleTitle: "A sensible basic setup",
      example:
        "Keep two encrypted .age backups on independent media, keep the private age identity elsewhere, and test them together before depositing funds."
    ),
    HelpTopic(
      id: "bip39", symbol: "key.horizontal", title: "BIP-39 mnemonic and passphrase",
      introduction:
        "A mnemonic is an ordered list of 12, 15, 18, 21, or 24 words encoding wallet entropy. Its checksum catches many typing errors, but cannot prove that it belongs to the wallet you intended.",
      bullets: [
        "A BIP-39 passphrase is an optional extra input, not an ordinary password that unlocks the words.",
        "Every passphrase—including a typo or an empty value—creates a different valid wallet without an error.",
        "Capitalization, spaces, spelling, and Unicode characters must match exactly.",
        "Fortress can compare two entries; only matching an address you already know proves the intended wallet.",
      ], exampleTitle: "Why address comparison matters",
      example:
        "Words with no passphrase produce Wallet A. The same words with ‘Blue Harbor 7’ produce Wallet B; ‘Blue Harbour 7’ produces Wallet C. All three are valid."
    ),
    HelpTopic(
      id: "age", symbol: "lock.shield", title: "age encryption: recipient and identity",
      introduction:
        "age encrypts with a public recipient and decrypts with its matching private identity. Fortress ships with a verified age binary and checks authenticated updates at startup.",
      bullets: [
        "A recipient usually begins with age1… and is safe to copy or share; it cannot decrypt.",
        "An identity usually begins with AGE-SECRET-KEY-… and must stay private.",
        "The encrypted file is useless without the identity, and the identity has nothing to decrypt without the file.",
        "Do not store the only identity beside every backup copy or in the same cloud account.",
      ], exampleTitle: "Separate the two sides",
      example:
        "Place encrypted backups on two USB drives in separate locations. Keep the private identity on another offline medium. Retain the public recipient wherever future backup creation is convenient."
    ),
    HelpTopic(
      id: "sskr", symbol: "point.3.connected.trianglepath.dotted", title: "What SSKR is for",
      introduction:
        "SSKR divides seed entropy into threshold recovery shares. Recovery succeeds only when enough groups participate and each participating group contributes enough distinct shares.",
      bullets: [
        "The group threshold is the number of groups required; the member threshold is the number of distinct shares required inside each participating group.",
        "For 2 of 3 groups and 2 of 3 shares per group, recovery needs two shares from each of any two groups: four shares minimum.",
        "Duplicate shares do not count. Record each share’s group and mnemonic language without changing its words or order.",
        "SSKR distributes trust and tolerates loss; age keeps a file confidential. They solve different problems and can be used together.",
        "If every share remains only inside one encrypted file, that file remains a single point of loss. Export shares separately for real distribution.",
      ], exampleTitle: "Practical 2-of-3 arrangement",
      example:
        "Group A is a home safe, B is trusted family, and C is a bank box. Requiring 2-of-3 shares in any 2 groups tolerates one missing share or one unavailable group, but one group alone cannot recover."
    ),
    HelpTopic(
      id: "workflow", symbol: "checklist", title: "Safe first-backup workflow",
      introduction:
        "Use a trusted, preferably offline computer. Do not deposit real funds until the complete recovery test succeeds.",
      bullets: [
        "1. Generate or enter the mnemonic, select its actual wordlist, and require checksum validation.",
        "2. Decide whether an optional passphrase belongs inside the encrypted file or in a separate recovery record.",
        "3. Choose a direct mnemonic backup for simplicity, or SSKR when multiple people or places must cooperate.",
        "4. Create or select an age identity you control, confirm its public recipient, then encrypt without overwriting a verified backup.",
        "5. Copy the encrypted file to another physical location and distribute exported SSKR shares according to the threshold plan.",
        "6. Open the stored file using the stored identity, reveal the recovered words, and derive a known address.",
        "7. Match that address against the real wallet, then clear sensitive data and close Fortress.",
      ], exampleTitle: "Test with a small amount first",
      example:
        "After the address matches, receive a small amount and verify it in the actual wallet. Repeat recovery using only stored materials, not values still open on the setup computer."
    ),
    HelpTopic(
      id: "storage", symbol: "archivebox", title: "What to store where",
      introduction:
        "A recovery plan contains several independent materials. Arrange them so one accident, theft, or account compromise cannot expose or destroy everything.",
      bullets: [
        "Encrypted .age backup: keep at least two copies on separate media or locations.",
        "Private age identity: keep offline and apart from encrypted backups.",
        "Public age recipient: copy freely wherever future encryption is convenient.",
        "SSKR shares: separate by group, person, or location and label their group numbers and thresholds.",
        "BIP-39 passphrase: preserve exact characters in a durable, separate record if one was used.",
        "Recovery map: leave understandable instructions describing the materials, thresholds, and where authorized people should look.",
      ], exampleTitle: "Avoid fake redundancy",
      example:
        "A laptop, its synced folder, and a USB inside the laptop bag can disappear in one incident. Count independent failure domains, not files."
    ),
    HelpTopic(
      id: "drill", symbol: "checkmark.shield", title: "Recovery drill and failure cases",
      introduction:
        "Run a drill whenever you create a backup, change a passphrase or SSKR plan, replace media, or transfer responsibility.",
      bullets: [
        "Open the stored encrypted file with the identity that is actually in storage—not a convenient cached copy.",
        "For SSKR, recover with the planned minimum threshold and confirm that insufficient combinations fail.",
        "Compare the network, address type, derivation path, and at least one address already verified in the wallet.",
        "Backup lost + identity present means nothing to decrypt. Backup present + identity lost means it cannot be decrypted. Too few SSKR shares means no reconstruction.",
        "Correct words plus a missing or wrong passphrase produce another valid wallet, often showing zero balance with no explicit error.",
        "Do not photograph, screen-share, paste into chat, or print secrets through an untrusted device. Clear sensitive data when finished.",
      ], exampleTitle: "The final proof",
      example:
        "A valid checksum alone is not enough. Successful decryption, successful SSKR reconstruction when applicable, and a known-address match form meaningful end-to-end verification."
    ),
  ]

  private static let chineseHelp = [
    HelpTopic(
      id: "purpose", symbol: "shield.lefthalf.filled", title: "Fortress 的用途",
      introduction: "Fortress 是离线备份与核对钱包恢复资料的工具。它不是钱包，不会发送交易、连接区块链、查询余额或保管资产。",
      bullets: [
        "它会验证 BIP-39 助记词，并将助记词或 SSKR 份额加密为 age 文件。",
        "日后可打开该文件并派生公开地址作核对；Rust 核心不会把派生私钥交给 Swift 界面。", "加密解决内容泄露问题；异地副本和恢复演练解决资料丢失问题。",
      ], exampleTitle: "合理的基础配置",
      example: "在独立介质上保留两份加密 .age 备份，把私密 age identity 放在别处，并在存入资产前完成一次实际解密测试。"),
    HelpTopic(
      id: "bip39", symbol: "key.horizontal", title: "BIP-39 助记词与附加密码",
      introduction: "助记词是按固定顺序排列的 12、15、18、21 或 24 个词，用来编码钱包熵。校验和能发现许多输入错误，却不能证明它就是你想恢复的钱包。",
      bullets: [
        "BIP-39 附加密码是可选的额外输入，并非用于“解锁”助记词的普通密码。", "任何附加密码——包括输错一个字或留空——都会生成另一个有效钱包，不会报错。",
        "大小写、空格、拼写及 Unicode 字符必须完全一致。", "Fortress 可以确认两次输入是否相同；只有匹配一个已知地址，才能证明是目标钱包。",
      ], exampleTitle: "为何必须比对地址",
      example: "助记词不加附加密码得到钱包 A；同一组词加“Blue Harbor 7”得到钱包 B；写成“Blue Harbour 7”则得到钱包 C。三者全部有效。"),
    HelpTopic(
      id: "age", symbol: "lock.shield", title: "age 加密：recipient 与 identity",
      introduction:
        "age 使用公开 recipient 加密，使用配对的私密 identity 解密。Fortress 内置经过验证的 age，并在启动时检查经过认证的更新。",
      bullets: [
        "recipient 通常以 age1… 开头，可以复制或分享，无法用于解密。", "identity 通常以 AGE-SECRET-KEY-… 开头，必须保密。",
        "只有 identity 而没有加密文件，无内容可解；只有文件而失去 identity，则无法解密。",
        "不要把唯一的 identity 与所有备份放在一起，也不要全部存进同一个云端账户。",
      ], exampleTitle: "把两侧分开保管",
      example: "将两份加密备份放在不同地点的 USB 中；把私密 identity 放在另一离线介质；公开 recipient 则可保存在方便日后创建备份的位置。"),
    HelpTopic(
      id: "sskr", symbol: "point.3.connected.trianglepath.dotted", title: "SSKR 解决什么问题",
      introduction: "SSKR 将助记词熵分割为带门限的恢复份额。只有达到足够组数，而且每个参与组内也有足够且互不重复的份额，才能恢复。",
      bullets: [
        "组门限代表需要多少个组参与；组内门限代表每个参与组需要多少个不同份额。", "若设置为 3 组取 2 组、每组 3 份取 2 份，则任意两组各提供两份即可，最少共 4 份。",
        "重复份额不计数。请记录所属组及词表语言，不得改变词语或顺序。", "SSKR 用于分散信任并承受丢失；age 用于隐藏文件内容。两者职责不同，可以结合使用。",
        "若所有份额只放在一个加密文件中，该文件仍是单一丢失点。要真正分散，必须分别导出并保管。",
      ], exampleTitle: "实用的 2-of-3 组方案",
      example: "A 组放家中保险箱，B 组交可信家人，C 组放银行保管箱。任意两组各取 3 份中的 2 份即可恢复；少一份或少一整组仍可恢复，但只有一组不行。"),
    HelpTopic(
      id: "workflow", symbol: "checklist", title: "安全的首次备份流程",
      introduction: "请使用可信、最好离线的电脑。在完整恢复测试成功前，不要存入真实资产。",
      bullets: [
        "1. 生成或输入助记词，选择其真实词表，并等待校验和通过。", "2. 决定可选附加密码应存入加密文件，还是作为独立恢复资料另行保管。",
        "3. 重视简单性时直接备份助记词；需要多人或多地点协同时使用 SSKR。",
        "4. 创建或选择你掌握的 age identity，确认公开 recipient 后再加密，且不要覆盖唯一已验证备份。",
        "5. 将加密文件复制到另一物理地点，并按门限计划分发已导出的 SSKR 份额。", "6. 使用实际保存的 identity 打开实际保存的文件，显示恢复词语并派生已知地址。",
        "7. 与真实钱包地址比对；确认一致后清除敏感资料并关闭 Fortress。",
      ], exampleTitle: "先用小额测试", example: "地址一致后先接收小额资产，并在真实钱包中确认。再只使用已保存的材料完成恢复，不要依赖设置电脑上仍然打开的数据。"),
    HelpTopic(
      id: "storage", symbol: "archivebox", title: "各种资料应放在哪里",
      introduction: "恢复计划包含多种相互独立的资料。应避免一次事故、盗窃或账户失陷同时泄露或毁掉全部材料。",
      bullets: [
        "加密 .age 备份：至少两份，分别放在独立介质或地点。", "私密 age identity：离线保存，并与加密备份分离。",
        "公开 age recipient：不是秘密，可复制到方便日后加密的位置。", "SSKR 份额：按组、人员或地点分开，并标注组号与门限。",
        "BIP-39 附加密码：若有使用，必须准确保存每个字符，并采用耐久的独立记录。", "恢复地图：留下授权人员能理解的说明，写明材料类型、门限以及去哪里寻找。",
      ], exampleTitle: "避免虚假的冗余",
      example: "笔记本电脑、该电脑同步的文件夹，以及电脑包里的 USB，可能在一次事故中同时消失。应计算独立故障范围，而非文件数量。"),
    HelpTopic(
      id: "drill", symbol: "checkmark.shield", title: "恢复演练与失败情形",
      introduction: "每次创建备份、更改附加密码或 SSKR 方案、更换介质或移交责任后，都应做恢复演练。",
      bullets: [
        "用真正放进保管处的 identity 打开真正保存的加密文件，不要依赖设置电脑的缓存副本。", "SSKR 应使用计划中的最低门限完成恢复，并确认不足门限的组合确实失败。",
        "核对网络、地址类型、派生路径，以及至少一个已经在钱包中确认过的地址。",
        "备份丢失但 identity 仍在＝无文件可解；备份仍在但 identity 丢失＝无法解密；SSKR 份额不足＝无法重组。",
        "助记词正确但附加密码错误或缺失＝另一个有效钱包，通常只显示零余额而不会明确报错。", "不要拍照、共享屏幕、贴入聊天，或通过不可信设备打印敏感资料；完成后立即清除。",
      ], exampleTitle: "最终证明", example: "校验和有效只是必要条件。成功解密、适用时成功重组 SSKR，以及匹配已知地址，三者一起才构成有意义的端到端验证。"),
  ]

  private static let japaneseHelp = englishHelp.map { topic in
    let localized: [String: (String, String, [String], String, String)] = [
      "purpose": (
        "Fortress が行うこと",
        "Fortress はウォレット復元情報をオフラインでバックアップ・検証するツールです。ウォレットではなく、送金、ブロックチェーン接続、残高照会、資産保管は行いません。",
        [
          "BIP-39 ニーモニックを検証し、ニーモニックまたは SSKR シェアを age ファイルへ暗号化します。",
          "後でファイルを開き、秘密鍵を Swift 側へ返さず公開アドレスを導出して確認できます。", "暗号化は漏えいを防ぎ、別媒体の複製と復元テストは紛失に備えます。",
        ], "基本的で堅実な構成",
        "暗号化 .age バックアップを独立した媒体に 2 部保管し、秘密 age identity は別の場所へ置きます。入金前に実際の復号テストを完了してください。"
      ),
      "bip39": (
        "BIP-39 ニーモニックとパスフレーズ",
        "ニーモニックはウォレットのエントロピーを表す、順序付きの 12、15、18、21、24 語です。チェックサムは多くの入力ミスを検出しますが、目的のウォレットかどうかまでは証明できません。",
        [
          "BIP-39 パスフレーズは任意の追加入力で、単語を解除する普通のパスワードではありません。",
          "空欄や 1 文字の誤りを含め、すべてのパスフレーズがエラーなく別の有効なウォレットを作ります。", "大文字小文字、空白、綴り、Unicode 文字まで完全一致が必要です。",
          "Fortress は 2 回の入力一致を確認できますが、目的のウォレットかどうかは既知アドレスとの照合が必要です。",
        ], "アドレス照合が必要な理由",
        "単語のみで Wallet A、同じ単語 +「Blue Harbor 7」で Wallet B、「Blue Harbour 7」で Wallet C になります。すべて有効です。"
      ),
      "age": (
        "age 暗号化：recipient と identity",
        "age は公開 recipient で暗号化し、対応する秘密 identity で復号します。Fortress は検証済み age を同梱し、起動時に認証済み更新を確認します。",
        [
          "recipient は通常 age1… で始まり、共有可能ですが復号には使えません。", "identity は通常 AGE-SECRET-KEY-… で始まる秘密情報です。",
          "ファイルだけ残っても identity を失えば復号できず、identity だけでは復号対象がありません。",
          "唯一の identity を全バックアップの隣や同じクラウドアカウントに置かないでください。",
        ], "2 つを分離する",
        "暗号化バックアップは別々の場所の USB 2 本へ。秘密 identity は別のオフライン媒体へ。公開 recipient は将来の暗号化に便利な場所へ置けます。"
      ),
      "sskr": (
        "SSKR を使う目的",
        "SSKR はシードのエントロピーを、しきい値付き復元シェアへ分割します。必要なグループ数と各参加グループ内の異なるシェア数を満たしたときだけ復元できます。",
        [
          "グループしきい値は必要グループ数、メンバーしきい値は各参加グループ内の必要シェア数です。",
          "3 グループ中 2、各グループ 3 シェア中 2 なら、任意の 2 グループから各 2 シェア、最少 4 シェアが必要です。",
          "重複シェアは数えません。所属グループと言語を記録し、語や順番を変えないでください。", "SSKR は分散と紛失耐性、age はファイルの秘匿を担当し、併用できます。",
          "全シェアが 1 つの暗号化ファイル内だけなら、そのファイルは単一障害点です。実際に分散するには個別書き出しが必要です。",
        ], "実用的な 2-of-3 構成",
        "A は自宅金庫、B は信頼する家族、C は銀行貸金庫。任意の 2 グループから各 2 シェアで復元し、1 シェアまたは 1 グループの喪失に耐えます。"
      ),
      "workflow": (
        "安全な初回バックアップ手順", "信頼できる、できればオフラインのコンピュータを使い、完全な復元テストが成功するまで実資産を入金しないでください。",
        [
          "1. ニーモニックを生成または入力し、実際の単語リストを選んでチェックサムを検証します。",
          "2. 任意のパスフレーズを暗号化ファイル内に保存するか、別の復元記録へ置くか決めます。",
          "3. 単純さを優先するなら直接バックアップ、複数人・複数拠点の協力が必要なら SSKR を選びます。",
          "4. 自分が管理する age identity を作成・選択し、recipient を確認して暗号化します。",
          "5. 暗号化ファイルを別の物理拠点へコピーし、SSKR シェアを計画どおり配布します。",
          "6. 保管した identity で保管したファイルを開き、復元語を表示して既知アドレスを導出します。",
          "7. 実際のウォレットと照合後、機密情報を消去して Fortress を閉じます。",
        ], "最初は少額で試す", "アドレス一致後に少額を受け取り、実ウォレットで確認します。設定端末に開いた値ではなく、保管資料だけでもう一度復元してください。"
      ),
      "storage": (
        "何をどこに保管するか", "復元計画は複数の独立した資料で構成されます。1 回の事故、盗難、アカウント侵害ですべてが同時に漏えい・消失しない配置が必要です。",
        [
          "暗号化 .age バックアップ：異なる媒体や場所に最低 2 部。", "秘密 age identity：オフラインでバックアップと分離。",
          "公開 age recipient：秘密ではないため、将来の暗号化に便利な場所へ複製可能。", "SSKR シェア：グループ、人、場所ごとに分け、グループ番号としきい値を記載。",
          "BIP-39 パスフレーズ：使用した場合は全ての文字を正確に、耐久性のある別記録へ。", "復元マップ：権限を持つ人が理解できるよう、資料、しきい値、探す場所を説明。",
        ], "見かけだけの冗長化を避ける",
        "ノート PC、その同期フォルダ、PC バッグ内の USB は 1 回の事故で同時に失われ得ます。ファイル数ではなく独立した障害領域を数えてください。"
      ),
      "drill": (
        "復元テストと失敗例", "バックアップ作成、パスフレーズや SSKR 計画の変更、媒体交換、担当者の引き継ぎごとに復元テストを行ってください。",
        [
          "保管中の identity で保管中の暗号化ファイルを開き、設定端末のキャッシュへ依存しないでください。",
          "SSKR は計画上の最小しきい値で復元し、不足する組み合わせが失敗することも確認します。",
          "ネットワーク、アドレス種別、導出パス、ウォレットで確認済みのアドレスを照合します。",
          "バックアップ紛失 + identity あり＝対象なし。バックアップあり + identity 紛失＝復号不可。SSKR 不足＝再構成不可です。",
          "正しい単語 + 誤った／空のパスフレーズ＝別の有効なウォレットで、エラーなく残高 0 に見える場合があります。",
          "撮影、画面共有、チャットへの貼り付け、信頼できない機器での印刷を避け、終了後に消去します。",
        ], "最終的な証明", "チェックサム有効だけでは不十分です。復号成功、必要なら SSKR 再構成成功、既知アドレス一致までが有効なエンドツーエンド検証です。"
      ),
    ]
    let value = localized[topic.id]!
    return HelpTopic(
      id: topic.id, symbol: topic.symbol, title: value.0, introduction: value.1, bullets: value.2,
      exampleTitle: value.3, example: value.4)
  }

  private static let koreanHelp = englishHelp.map { topic in
    let localized: [String: (String, String, [String], String, String)] = [
      "purpose": (
        "Fortress가 하는 일",
        "Fortress는 지갑 복구 자료를 오프라인에서 백업하고 검증하는 도구입니다. 지갑이 아니며 거래 전송, 블록체인 연결, 잔액 조회 또는 자산 보관을 하지 않습니다.",
        [
          "BIP-39 니모닉을 검증하고 니모닉 또는 SSKR 조각을 age 파일로 암호화합니다.",
          "나중에 파일을 열고 파생 개인 키를 Swift 화면으로 반환하지 않은 채 공개 주소를 확인할 수 있습니다.",
          "암호화는 유출을 막고, 독립된 복사본과 복구 연습은 자료 손실에 대비합니다.",
        ], "합리적인 기본 구성",
        "암호화된 .age 백업을 독립된 매체 두 곳에 두고 비공개 age identity는 별도 보관하세요. 입금 전 실제 복호화 테스트를 완료하세요."
      ),
      "bip39": (
        "BIP-39 니모닉과 패스프레이즈",
        "니모닉은 지갑 엔트로피를 나타내는 순서가 정해진 12, 15, 18, 21 또는 24개 단어입니다. 체크섬은 많은 입력 오류를 찾지만 의도한 지갑인지는 증명하지 못합니다.",
        [
          "BIP-39 패스프레이즈는 선택적인 추가 입력이며 단어를 푸는 일반 비밀번호가 아닙니다.",
          "빈 값이나 한 글자 오타를 포함한 모든 패스프레이즈는 오류 없이 서로 다른 유효한 지갑을 만듭니다.",
          "대소문자, 공백, 철자와 Unicode 문자가 완전히 같아야 합니다.",
          "Fortress는 두 입력이 같은지만 확인하며, 의도한 지갑인지는 이미 아는 주소와 비교해야 합니다.",
        ], "주소 비교가 필요한 이유",
        "단어만 사용하면 Wallet A, 같은 단어에 ‘Blue Harbor 7’을 더하면 Wallet B, ‘Blue Harbour 7’이면 Wallet C이며 모두 유효합니다."
      ),
      "age": (
        "age 암호화: recipient와 identity",
        "age는 공개 recipient로 암호화하고 대응하는 비공개 identity로 복호화합니다. Fortress는 검증된 age를 포함하고 시작할 때 인증된 업데이트를 확인합니다.",
        [
          "recipient는 보통 age1…로 시작하며 공유할 수 있지만 복호화에는 쓰지 못합니다.",
          "identity는 보통 AGE-SECRET-KEY-…로 시작하는 비밀 정보입니다.",
          "파일만 있고 identity를 잃으면 복호화할 수 없고, identity만 있으면 복호화할 파일이 없습니다.",
          "유일한 identity를 모든 백업 옆이나 같은 클라우드 계정에 두지 마세요.",
        ], "두 요소를 분리하세요",
        "암호화 백업은 서로 다른 장소의 USB 두 개에, 비공개 identity는 별도 오프라인 매체에 두세요. 공개 recipient는 향후 암호화에 편한 곳에 보관할 수 있습니다."
      ),
      "sskr": (
        "SSKR의 목적",
        "SSKR은 시드 엔트로피를 임계값이 있는 복구 조각으로 나눕니다. 충분한 그룹이 참여하고 각 참여 그룹에 서로 다른 조각이 충분할 때만 복구됩니다.",
        [
          "그룹 임계값은 필요한 그룹 수, 멤버 임계값은 각 참여 그룹 안에서 필요한 서로 다른 조각 수입니다.",
          "3개 그룹 중 2개, 각 그룹 3개 중 2개라면 임의의 두 그룹에서 각 2개씩 최소 총 4개가 필요합니다.",
          "중복 조각은 계산되지 않습니다. 그룹과 언어를 기록하고 단어나 순서를 바꾸지 마세요.",
          "SSKR은 분산과 손실 내성을, age는 파일 기밀성을 담당하며 함께 사용할 수 있습니다.",
          "모든 조각이 파일 하나 안에만 있으면 그 파일은 단일 손실 지점입니다. 실제 분산을 위해 개별 내보내기를 사용하세요.",
        ], "실용적인 2-of-3 구성",
        "A는 집 금고, B는 신뢰하는 가족, C는 은행 보관함에 둡니다. 임의의 두 그룹에서 각 2개로 복구하며 조각 하나나 그룹 하나를 잃어도 견딥니다."
      ),
      "workflow": (
        "안전한 첫 백업 절차", "신뢰할 수 있고 가능하면 오프라인인 컴퓨터를 사용하세요. 전체 복구 시험이 성공하기 전에는 실제 자산을 넣지 마세요.",
        [
          "1. 니모닉을 생성하거나 입력하고 실제 단어 목록을 선택해 체크섬을 검증합니다.",
          "2. 선택적 패스프레이즈를 암호화 파일 안에 둘지 별도 복구 기록에 둘지 정합니다.",
          "3. 단순함이 중요하면 직접 백업을, 여러 사람·장소의 협력이 필요하면 SSKR을 선택합니다.",
          "4. 직접 관리하는 age identity를 만들거나 선택하고 recipient를 확인한 뒤 암호화합니다.",
          "5. 암호화 파일을 다른 물리적 장소에 복사하고 SSKR 조각을 계획대로 배포합니다.",
          "6. 보관한 identity로 보관한 파일을 열고 복구 단어를 표시해 알고 있는 주소를 파생합니다.",
          "7. 실제 지갑 주소와 비교한 뒤 민감한 정보를 지우고 Fortress를 닫습니다.",
        ], "먼저 소액으로 시험하세요",
        "주소가 일치하면 소액을 받은 뒤 실제 지갑에서 확인하세요. 설정 컴퓨터에 열려 있는 값이 아니라 보관 자료만으로 다시 복구하세요."
      ),
      "storage": (
        "무엇을 어디에 보관할까",
        "복구 계획은 서로 독립된 여러 자료로 구성됩니다. 한 번의 사고, 도난 또는 계정 침해가 모든 자료를 동시에 노출하거나 없애지 않게 배치해야 합니다.",
        [
          "암호화된 .age 백업: 서로 다른 매체나 장소에 두 개 이상.", "비공개 age identity: 오프라인에서 암호화 백업과 분리.",
          "공개 age recipient: 비밀이 아니므로 향후 암호화에 편한 곳에 복사 가능.",
          "SSKR 조각: 그룹, 사람 또는 장소별로 분리하고 그룹 번호와 임계값 표시.",
          "BIP-39 패스프레이즈: 사용했다면 모든 문자를 정확히 별도의 내구성 있는 기록에 보존.",
          "복구 지도: 권한 있는 사람이 이해하도록 자료, 임계값과 찾을 장소를 설명.",
        ], "가짜 중복 보관을 피하세요",
        "노트북, 그 노트북의 동기화 폴더, 가방 속 USB는 한 사건으로 모두 사라질 수 있습니다. 파일 수가 아니라 독립된 장애 영역을 세세요."
      ),
      "drill": (
        "복구 연습과 실패 사례", "백업 생성, 패스프레이즈나 SSKR 계획 변경, 매체 교체 또는 책임 이전 때마다 복구 연습을 수행하세요.",
        [
          "실제 보관한 identity로 실제 보관 중인 암호화 파일을 열고 설정 컴퓨터의 캐시에 의존하지 마세요.",
          "SSKR은 계획한 최소 임계값으로 복구하고 부족한 조합이 실패하는지도 확인하세요.",
          "네트워크, 주소 유형, 파생 경로와 지갑에서 확인한 주소를 비교하세요.",
          "백업 분실 + identity 보유 = 대상 없음. 백업 보유 + identity 분실 = 복호화 불가. SSKR 부족 = 재구성 불가입니다.",
          "올바른 단어 + 틀리거나 빈 패스프레이즈 = 다른 유효한 지갑이며 오류 없이 잔액 0으로 보일 수 있습니다.",
          "촬영, 화면 공유, 채팅 붙여넣기, 신뢰하지 않는 기기로 인쇄하지 말고 완료 후 민감한 정보를 지우세요.",
        ], "최종 증명", "체크섬 유효만으로는 부족합니다. 복호화 성공, 필요한 경우 SSKR 재구성 성공, 알고 있는 주소 일치까지가 의미 있는 종단 간 검증입니다."
      ),
    ]
    let value = localized[topic.id]!
    return HelpTopic(
      id: topic.id, symbol: topic.symbol, title: value.0, introduction: value.1, bullets: value.2,
      exampleTitle: value.3, example: value.4)
  }
}
