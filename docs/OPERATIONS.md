# OAuth・サービス鍵・更新・復旧

この文書は実装した操作の契約です。物理デバイスの実験は利用者指定で除外しています。Mac/Linuxの実行結果は各manifestで確認します。形式保証の契約はPROOF_CONTRACT.mdに記載します。

## OAuth ASの接続

brokerの`oauth`に`client_id`、`authorization_endpoint`、`token_endpoint`、`redirect_uri`、任意の`ca`を設定します。ASのissuerと両endpointは同じHTTPS originを使います。callbackは例えば`http://127.0.0.1:49152/callback`で、固定登録したloopback IPと明示portが必要です。ASにはnative/public client、code flow、S256 PKCE、DPoP bound token、callbackの`iss`返却を登録します。HTTP callbackはcode受取だけで、Vaultとの通信はlocalでもhostedでもHTTPSです。

brokerへowner署名済みGrantだけを渡すと、brokerはcallbackをbindした後、`authorization_url`を出力します。管理者が信頼するブラウザでログイン・同意します。brokerはstateとissuerを検査し、保持しているPKCE verifierとDPoP秘密鍵でcodeを交換します。token endpointのDPoP nonce要求にはfresh proofで一度だけ再試行します。未使用codeに対する異なるverifier・異なる鍵の拒否、code replay、改変state／issuerは実AS試験の対象です。

ASが発行するtokenはES256 `typ=at+jwt`で、`iss`、文字列`aud`、`sub`、`nbf`、`exp`、`scope`、UUID `grant_id`、`cnf.jkt`が必要です。issuer公開鍵はVault側で固定し、token内のjwkによる差替えを拒否します。ASは承認したowner Grantを検査して同じsubject／grant ID／scope／DPoP thumbprintを発行してください。`vault_grant` request parameterにowner署名付きGrantを渡します。Vaultも各項目を独立に再検査します。

`tools/oauth-as`は固定データでlogin/consentを完了する**試験用**fixtureです。OIDC/OAuthエンジンにはoidc-provider 9.13.3を使い、実際のHTTPS・PKCE・DPoP・認可コード処理を通します。このlogin handlerやin-memory adapterを本番ASとして使ってはいけません。本番のidentity／MFA／consentは接続先ASの責任です。

AS鍵の更新は、新旧公開鍵を自動取得せず、新しいTrust設定・配置証跡を受け入れて再起動します。旧tokenが継続利用できる重複期間は設けていないため、新issuer鍵のtokenを取得し直します。

## 起動時に一度解錠するサービス鍵

owner/device/guardianの操作承認鍵と、witness/operator/DB用のservice鍵は区別します。対話承認鍵にはnative Secure Enclave／TPMを使います。service鍵はP-256で生成し、hardware protectorの公開鍵に暗号化したenvelopeだけを保存します。

```sh
vault-rs generate-service-key --protector-public /etc/vault-rs/protector.pub --purpose signing
vault-rs generate-service-key --protector-public /etc/vault-rs/protector.pub --purpose agreement
```

出力JSONの`envelope`をroot管理の0600ファイルへ保存し、同時に出る`public_key`を設定へ固定します。RuntimeKeyConfigは従来のNativeConfig、または`{protector:<NativeConfig>,envelope:<absolute path>,purpose:"signing"|"agreement",public_key:<pinned key>}`です。サービス起動時にprotectorが解錠し、purposeと公開鍵が一致した鍵だけをメモリへ読みます。以後の各要求でPINは必要ありません。終了後の再起動には再び解錠が必要です。

resident鍵はプロセスメモリに存在するソフトウェア鍵です。鍵自体が持出し不能だとは主張しません。rootとAIのUID分離、core禁止、Linuxのdump禁止、改変不可の設定／実行物、独立guardianが防御境界です。稼働中のrootメモリまで支配する攻撃はTCB侵害です。PCの電源断／ロック、ディスク暗号化、swap管理は配置先の責任です。物理攻撃への抵抗を、resident鍵の単体試験で代替しません。

Macではnative configに`macos_uid`が必要です。AIとは別の専用ログインユーザーを指定し、そのユーザーのKeychainとGUI sessionを使います。root launch daemonでData Protection Keychain UIを直接開く構成は採用しません。Linuxでは`macos_uid`を指定すると拒否します。

## 鍵ローテーション

SQLCipher DBの更新は旧ファイルへの上書きでなく、新しいDB generationを作ります。

```sh
vault-rs rotate-storage --source /var/lib/vault-rs/old.db \
  --destination /var/lib/vault-rs/new.db \
  --old-key /etc/vault-rs/old-key.json --new-key /etc/vault-rs/new-key.json
```

1. 対象サービスを停止します。DBを開いたサービスはshared flockを保持し、rotationはexclusive flockを取れなければ拒否します。
2. 旧DBを旧鍵で開き、WALをcheckpointします。新しいランダムDEKを生成し、新protectorにラップします。
3. `sqlcipher_export`で新DBに移し、新鍵で再openしintegrityを検査してfile/directoryをfsyncします。旧generationはbackupとして残ります。
4. 出力が`prepared`であることを確認し、新DB pathと新鍵を使う設定の配置証跡を受け入れて再起動します。途中失敗したdestinationは未公開のまま保全し、別の新しいpathで再試行します。自動的に旧設定へ戻しません。

既存DBのDEKだけを再ラップする処理ではありません。試験では新DBを旧鍵／旧envelopeで開けないことを確認します。旧backup自体を旧鍵で開けることは当然残るため、旧鍵廃止とbackup保持期限を管理します。廃棄済み媒体の物理消去を本プログラムが保証することはありません。

provider DSNやresident-key envelopeは`rewrap-config --source ... --destination ... --old-key ... --new-key ...`で新protectorに再暗号化します。新envelopeを新鍵で開けることを検査してから書き、新設定は別途受け入れます。

E2E recordは`RecipientSession::rotate_record`で更新します。旧recordへの正規のreleaseを完了してから新しいversionとDEKで再暗号化し、device/guardianの新しい公開鍵へ分割します。旧grantをowner-signed revokeまたはquarantineで廃止し、新record hashに対する新IDのGrantを承認します。rotationを理由に旧grantの残回数を復活させません。試験は独立に新規生成した鍵を使い、旧鍵による復号を拒否します。

## 障害と鍵喪失

- Vault DBだけを復旧する場合、現在の独立witnessと一致するgrantだけを継続できます。不一致はowner-signed quarantineで永久廃止し、新IDで再承認します。
- witnessは独立の管理・backupと最新状態の保持が必要です。Vaultとwitnessを同じ過去snapshotへ戻しません。最新witnessを失った場合は旧grantを再開せず、旧Vaultを停止し、新vault ID／新trust／新grantへ移行します。過去の承認情報から回数を再生しません。
- hardware protectorが失われた場合、失われる前に正規に準備した独立の復旧端点／暗号化backupが必要です。それも無ければ秘密を復号する方法はありません。availabilityのために認可を迂回して復号する手段は設けません。
- providerのoutboxは冪等なlease IDで再実行できます。失効時はNOLOGINをcommitしてから既存session終了／role dropへ進みます。provider停止中のPostgreSQL既存sessionに対するTTL強制は保証していません。これは動的credentialの残る運用制約です。

## 再現する試験

`test-deployment.sh`はrootless Docker内で本物のCLIを別プロセスとして起動します。HTTPS witness／Vault、二人のsubject、brokerのprivate control pipeと別UIDのworkload、resident鍵のstartup-only解錠、プロセス再起動、失効を確認します。native helperとissuer鍵は合成fixtureで、物理デバイス証跡には分類しません。`test-oauth.sh`はこれと別に実ASのprotocolエンジンを検査します。この二つを一つの本番配置で通したという主張はありません。

## 初回DB生成と設定測定

本番起動前にroot管理のcanonical absolute directoryを用意します。Macでは `/var` aliasを設定に使わず `/private/var` 等のcanonical pathを指定します。サービスとAIのアカウントを分離し、AIにsudo権限を与えません。設定・helper・CA・extension・provider envelopeをroot管理pathに置き、group/otherの書込みとMac extended ACLを除きます。

```sh
vault-rs initialize-storage --database /opt/vault-data/vault.db --key-config /opt/vault-config/decryption.json
vault-rs observe --config /opt/vault-config/server.json
```

initialize-storageは既存DB／鍵envelopeを上書きせず、新しい暗号化世代とそのdigestを作ります。サービスのdecryption RuntimeKeyConfigと同じ鍵を指定します。witness DBも同様です。observeのconfig hashは設定本体に加え、roleとcanonical pathを付けたhelper/CA/鍵envelope/provider/extension等の内容とDB鍵envelopeを束縛します。DBの可変pageは含めません。受入済みgenerationと違うenvelopeはunwrap前に拒否します。

以後、署名付きrelease/review/deploymentとauthority policyを登録し、readinessが成功した構成だけをserve/witness/brokerの `--acceptance` に渡します。releaseの配布物検証が完了していても、自分の配置を誰かが承認したことにはなりません。必要な署名は登録した実際の権限主体が `approve` コマンドで行います。

稼働中の受入済みhelper・CA・provider config等の上書きは禁止です。更新は停止→新世代pathへの配置→observe→再承認→起動の順で行います。rootの悪意ある変更はこの保証の外ですが、誤った同時更新も避けます。token期限が30秒より短い場合もoperation期限をtokenに合わせ、device操作中に期限が過ぎればworkloadへ値を渡しません。

## 検証済み配布物の取得

同一 GitHub Actions run の `production-software-release` artifact に、Linux/macOS の native binary、Mac helper、全検証ログ、ソース、`release.json`、`SHA256SUMS` をまとめます。`release-evidence` job は両 OS の job 成功後だけ実行し、ソース全ファイルと binary/log hash の一致を検査します。失敗した run の中間 artifact は製品の受入証跡に使いません。workflow の commit と出所も確認してください。hash 単独では配布者を認証できません。

Linux 配布 binary は Ubuntu 24.04 x86_64（glibc 2.39、OpenSSL 3）向けです。Mac 配布 binary は macOS 15 arm64、Homebrew OpenSSL 3 (`brew install openssl@3`) を使います。他の OS version／architecture は同じソースから再 build・再検証してください。artifact 展開後は `sha256sum -c SHA256SUMS`（Mac は `shasum -a 256 -c SHA256SUMS`）で内容を検査し、対象 binary を root 管理 path へ `install -m 755` で配置します。macOS helper は専用ユーザーの Keychain と署名・entitlement 設定が別途必要です（HARDWARE.md）。

source.tar.gz は検証対象ソース一式です。Rust toolchain は rust-toolchain.toml、crate は Cargo.lock、CI action は commit SHA に固定しています。ソースを展開して git repository を初期化し、`scripts/prepare-tools.sh` と `scripts/verify.py --with-docker` で Linux 証跡を再生成できます。Mac は workflow の native 手順を実行します。再生成は新しい証跡となり、元の承認署名を引き継ぎません。

リリースは `scripts/build-release.sh` に同一のfeature／target選択を集約します。ThinLTOの内部symbol／配置がキャッシュ有無で変わる診断結果に対応し、releaseではLTOを無効化しcodegen-units=1を指定します。性能最適化より同じ条件での全byte再現を優先する設定で、検査は引き続きbinary全体のSHA-256一致を要求します。
