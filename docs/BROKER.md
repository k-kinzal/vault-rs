# Broker・承認・本番受入

この手順は現在の実装契約を説明するものです。Mac／実TPMを使った完成済み運用手順ではありません。本番受入の状態はPRODUCTION_GOAL.mdとASSURANCE.mdが正本です。

## 身元と実行物

AIはbrokerと異なる非特権UIDで動かします。AIにsudo権限やroot管理ファイルの書込権限があればこの境界は成立しません。brokerは管理者が起動するone-shotプロセスです。公開socket、任意message署名API、AIが使えるsudo wrapperは設けません。

bundle JSONは`entrypoint`、`arguments`、`files[{path,contents,executable}]`です。contentsはbase64url（paddingなし）。最大32MiB、512ファイル。全ファイルと引数をhashに含め、root管理directoryへcreate_newで展開し、ファイル444/555・directory555へ固定します。symlinkや相対pathの脱出を拒否します。コードを追加／変更したら新しいowner承認が必要です。

```sh
vault-rs measure-bundle --bundle /etc/vault-rs/tool.bundle.json
```

実行物のOSライブラリ／interpreterはTCBです。bundle以外の依存を勝手に取得して実行するツールを、hashだけで安全と判断しません。Python等の利用者インストール・親プロセスの環境を引き継ぎません。依存ファイルはbundleに含め、system runtimeも承認された配置先で管理します。

UIDは専用namespaceのwitness revisionから一度だけ割り当てます。`uid_base >= 10000`、`uid_limit <= 2000000000`、既存OS account/groupとAI UIDの範囲外が必要です。witness／namespace／範囲のリセット、他brokerによる同じUID範囲の使用は禁止です。使い切った範囲は再利用せず、新しい未使用範囲・namespaceを管理者が登録します。broker用allocatorには、そのoperatorだけを認める独立したWitnessAuthorityの配置を使います。

## 一回の利用

brokerのstdin/stdoutは管理者が保持するprivate pipeです。端末・FIFO・制御ソケットをAIと共有しません。作業ツールへのstdinは別に生成する専用pipeです。

1. `broker --config ... --acceptance ...`を管理者として起動。
2. brokerが公開IntentをJSON一行で出力。recipient、DPoP公開JWK、instance、artifact hash、秘密のID／版／hash、subject、device公開鍵が含まれます。秘密鍵は出ません。
3. ownerがこのIntentを確認しGrantに署名。ASが同じsubject、grant ID、DPoP thumbprint、scopeに束縛したアクセストークンを発行。管理者が`{"grant":<Signed<Grant>>,"access_token":"..."}`をstdin一行で渡します。`oauth`設定がある場合はtokenを省略でき、brokerが認可URLを出力してloopback callbackを待ちます。PKCE verifier／DPoP鍵はbroker内に保持し、認可コードをASへ交換します。実ASとの試験は`test-oauth.sh`を参照。
4. brokerがinstallとchallengeを実行し、完全なOperationを公開出力。独立guardianが内容を確認し署名します。
5. 管理者が`{"guardian_signature":"..."}`を渡すと、brokerは他の全認可を検査した後でdevice鍵の確認画面／PINを要求します。
6. witnessでUIDを予約し、release／issue、SDKでの検証・復号、別UIDの実行へ進みます。ツールに渡すのは許可された秘密値だけです。

`approve --key-config /etc/vault-rs/owner.json --kind grant`はstdinのGrantを型付きで読み、owner-grant domainに署名したSigned<Grant>を返します。`guardian-operation`、`revoke`、`quarantine`、`release`、`review`、`deployment`も同様です。guardianの出力はSigned<Operation>なので、そのsignature fieldをbrokerに渡します。generic JSON Valueのkey順に依存して署名してはいけません。

承認用native helperは対話式です。witness/operator署名とservice復号にはresident keyを選択でき、起動時だけnative protectorを解錠します。以降のリクエストにはPINを要求しません。`test-deployment.sh`で実CLIの起動・二人の取得・再起動・回数保存を検証します。PINを環境変数／設定へ平文保存しません。30秒の認可期限内に承認が終わらなければ拒否し、新しいOperationを承認します。

Linuxの試験では別UIDによるメモリ／FD／鍵ファイル読取・実行物書換え・broker直接起動を拒否し、正規stdinだけの受渡しを確認します。Linuxにはno_new_privs、core禁止、資源制限を適用します。Mac ARM64のRust／Swiftはクロスビルド済みです。root brokerから専用のGUIユーザーへ`launchctl asuser`とUID変更を行い、Data Protection Keychainを呼ぶ実装です。Mac上のOS隔離／Keychain実行は未実施です。

timeoutではprocess groupを終了しますが、setsidした子孫全体の終了は保証しません。子孫は再利用されないUIDと既に許可された秘密値しか持ちません。完全なjob lifecycle制御は別の残課題です。

## 復旧

witnessとDBが不整合なら、自動で古いsnapshotを採用しません。

1. owner署名済みGrantを`POST /v1/checkpoint`へ送り、独立witnessの現在値を取得。
2. `{vault,grant,expected:{revision,hash}}`に`approve --kind quarantine`で署名し、`POST /v1/quarantine`へ送信。
3. witness CASとDB確定により、そのIDを永久廃止。別の未使用IDでowner承認をやり直します。使い残した回数の復活はしません。

途中失敗なら新しいcheckpointを取得して再承認が必要です。quarantine後のprovider cleanupだけが失敗した場合は、同じgrantにowner-signed `/v1/revoke`を送って再試行できます。DB／E2E／設定鍵のrotation、鍵紛失時の停止と独立witnessを保持する復旧手順は[OPERATIONS.md](OPERATIONS.md)にあります。失った復号鍵を無条件に再生するbackdoorはありません。witness最新状態も失った場合は旧grantの再開を拒否します。

## 本番受入

`AcceptanceFiles{policy,bundle,logs}`をroot管理pathに置きます。物理鍵試験を除外する場合は`allow_physical_test_exclusion:true`をpolicyに、`physical_tests_excluded:true`を署名対象Releaseに記録します。他の受入条件は残ります。policyは別々に登録したrelease/review/deployment公開鍵、minimum_epoch、有効期間の上限（最大30日）。bundleはSigned<Release>、Signed<Review>、Signed<Deployment>です。

Releaseはsource hash、Mac/Linux各binary hash、G01〜G13×両OSの結果とmethod・ログpath・SHA-256を指定します。Reviewは同じreleaseのhashと未解決指摘0を承認します。Deploymentは同じrelease、実host、実binary、設定hash、OSと期限を束縛します。`observe --config ...`で実測値を出せますが、acceptance署名は作りません。

readinessは署名・完全性・method・hash・期限を検査します。起動時に検査し、受入証跡の最短期限でプロセスを停止します（監視間隔1秒、信頼できる時計を前提）。新しい受入には明示的な再起動が必要です。検証者が実際に試験したか、三つの鍵が異なる管理者か、ログ内容が定理を証明するかは、承認者の責任と独立レビューが必要です。署名検査がログ内容の真実性を自動証明するとは主張しません。

単体テスト中のsynthetic acceptance成功例は検査器を試すためだけのものです。証跡としてexportせず、本番判定の成功として報告しません。
