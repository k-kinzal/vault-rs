# 内蔵鍵を標準にする構成

外部HSMだけを前提にしない。MacはSecure Enclave、LinuxはTPM 2.0を標準の実現対象とし、PKCS#11はオプション。実行時に利用できなければ起動／操作を拒否し、ソフトウェアPEMへ自動退避しない。

| 環境 | バックエンド | 保護と現在の証跡 |
|---|---|---|
| Secure Enclave搭載Mac | Security.framework、P-256署名／ECDH | Apple SDKでRust／SwiftのARM64 Mach-O生成済み。userPresence＋WhenUnlockedThisDeviceOnly。Mac上の実行は未実施 |
| Linux＋物理TPM2 | tpm2-tools、fixedTPM/fixedParent鍵、PIN | helper source提供。swtpmでコマンド形式・ECDH一致・署名・誤PIN拒否を実行。物理耐性の証拠ではない |
| 外部PKCS#11 | RSA-OAEP復号／ECDSA署名 | feature=pkcs11でコンパイル、実デバイス未接続 |
| 内蔵保護装置なし | 未対応 | ソフトウェア鍵だけで盗難耐性を同等としない。別の保護されたguardian端点を設ける必要あり |

## 鍵を分離する

owner署名、OAuth issuer、DPoP、device operation署名、guardian operation署名、device ECDH、guardian ECDH、witness/operator署名は役割が異なる。同じ鍵を使い回さない。owner登録時に二つの承認側の公開鍵と目的を確認する。

guardianをdeviceと同じ侵害可能なOSアカウントに置くと共倒れになる。単独利用でも独立したOS保護領域／ユーザー承認を必要とする。ローカル／hostedでこの条件は変わらない。vTPMはクラウド管理者を信頼する場合の保護領域で、管理者に対する非エクスポート性を自動的に保証しない。

## Native helper契約

Rustの`NativeKey`はcanonicalな絶対path、root所有かつgroup/other書込不可のhelperと親directory、SHA-256を検査する。環境をクリアしてhelperを起動し、stdin/stdoutの小さなJSON契約で`sign`または`ecdh`を呼ぶ。秘密鍵そのものを返すoperationはない。signはmessage全体を表示し、ECDHはrecord/storageのlabelを表示する。署名はRust側で登録公開鍵との一致も検証する。

この契約はgeneric signing oracleとしてAIに公開しません。Linux helperは実UID／実効UIDがroot以外なら拒否します。Mac helperは`macos_uid`に指定した専用ログインユーザーのGUIセッションで実行します。Rust側はrootから`launchctl asuser UID sudo -n -H -u #UID -- helper`を起動し、AI UIDと鍵所有者UIDが一致した構成を拒否します。Keychainアイテムは鍵所有者のユーザー領域に保存します。AIが自分のUIDで同名の鍵を生成しても登録公開鍵と異なるため利用できません。brokerの制御入力は管理者が保持するinherited pipeだけです。Macでこの経路を実行した証跡はまだありません。

### macOS

```sh
swiftc platform/macos/SecureEnclaveHelper.swift -o SecureEnclaveHelper
```

管理者が署名・entitlements・keychain access groupを定義して保護pathに配置する。安易なad-hoc codesignを本番の信頼根拠にしない。JSON `{operation:"create",key_id:"device-sign",data:"",context:"..."}` によりSecKeyを生成する（実際は正しいJSON quotingが必要）。公開鍵は65byte SEC1。暗号化用には`p256:`＋base64url、署名用には圧縮33byte SEC1へ変換して設定する。

`public`、`sign`、`ecdh`をサポート。生成時もユーザーに確認する。macOSのprompt再利用・ロック・アクセス制御の挙動は実機で検証するまで保証しない。外部画面のtrusted transaction表示やXPCサービスは今後実装する。

### Linux

管理者が実TPM `/dev/tpmrm0` にP-256鍵を登録する。キー属性は署名用`fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign`、ECDH用は最後を`decrypt`にする。`noda`を設定せずdictionary-attack保護を有効にする。PINは非空で端末から入力し、argv／環境へ置かない。

root管理の `/var/lib/vault-rs/tpm/<key_id>/` に `key.pub`、TPMにラップされた`key.priv`、`parent-handle`（`0x81......`）を置く。親は管理者が作成するpersistent storage parentで、既存handleを上書きしない。key.privは秘密鍵の平文exportではない。公開鍵fingerprintと属性の登録証跡を保存する。

現行helperはroot管理brokerだけが実行できます。AIのUIDをTPM/key directoryへアクセスできるgroupへ入れず、rootへの昇格手段を与えません。root所有のhelperへ`chmod 755`、directoryは管理者のみ変更可能にする。Python interpreterとtpm2-toolsもTCBである。

`platform/linux/enroll-tpm.py`は管理者が用意した既存persistent parentへ鍵を登録し、強いランダムauthorizationを`/dev/tty`に一度表示して保存確認を求めます。stdoutには公開情報だけを返し、既存鍵／parentを上書きしません。実TPM専用で、まだ実機で実行していません。

現在のhelperは`/dev/tty`へ承認対象を表示してPINを求める対話方式。認証ファイルはtmpfs内mode0600で一時的に生成し終了時に消す。PythonやTPM utility内のメモリの完全ゼロ化は保証しない。無人serviceには起動時に解錠するresident keyを使います（[OPERATIONS.md](OPERATIONS.md)）。owner/device/guardianの対話承認UIは分離します。PINのenv注入で無人化しません。

### PKCS#11

moduleをroot管理path＋digestで固定し、hardware slot、token serial、protected authentication pathを必須とする。private keyはSensitive/AlwaysSensitive/Local/NeverExtractable=true、Extractable=false。各fresh sessionで認証する。現在`AlwaysAuthenticate=true`鍵のcontext-specific loginは未実装なので拒否する。これらの属性はtrusted moduleの申告であり、remote attestationではない。

## 物理鍵実験（利用者指定で今回の受入から除外、すべて未実施）

1. 鍵の平文exportが不可能であり、wrapped blobを別端末へコピーしても操作できない。
2. ロック／再起動／ユーザー不在で拒否され、誤PIN制限や生体認証失敗が有効。
3. AIのUID・署名の異なるアプリ・デバッガ・別セッションからの呼出しを拒否する。
4. ユーザーが確認したresource/recipient/artifact以外を署名できず、差替えを拒否する。
5. DB・WAL・key envelopeだけを持つ別環境で開けない。
6. 未承認のbuild／helper／依存library更新を拒否し、正規更新と復旧の証跡を保存する。

TPM simulatorのPASSをこの受入試験のPASSに転記しない。
