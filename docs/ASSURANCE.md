# 保証範囲と証跡

**総合ゴールは未達です。`production_ready=false`であり、本番利用を承認できる証拠は揃っていません。** ゴールはPRODUCTION_GOAL.md v2のG01〜G13×Mac/Linuxです。利用者指定で物理鍵実験のみ除外します。

形式検証で保証したのは、明示した前提における一部の実コードと有限モデルです。JSON parser、署名検証、永続化、OS、native helperまで連続したサービス全体のrefinement証明はありません。「考慮漏れが一切ない」「未知の脆弱性がない」とは主張しません。

## ゴールへの対応

| ID | 実装・検証 | 未達／保証境界 |
|---|---|---|
| G01 | OAuth/DPoP＋device/guardian署名、Kani、盗難鍵・各field改変試験 | parser/crypto→Evidence生成全体の機械検証なし |
| G02 | root broker、使い捨てUID、private stdin。LinuxでAI UIDからのmemory/FD/file/code/sign経路拒否 | MacのRust/Swiftはクロスビルド済み、専用GUI UIDへ分離。Mac上の実OS隔離／Keychain実行は未検証 |
| G03 | immutable bundle＋全file/引数hash、private instance/recipient、差替え試験 | system runtimeはTCB。Mac ACL／更新時の実機攻撃試験未実施 |
| G04 | SE helper、TPM helper/enrollment、外部PKCS#11 optional | 物理デバイス実験は明示除外。swtpm結果を物理証跡にしない |
| G05 | SQLCipher DB/WAL、hardware-wrapped DB鍵、2-of-2 E2E、鍵なしopen失敗 | protector接続はnative profile／CLI fixtureで確認。物理デバイス実験は除外、swap／物理メモリはTCB境界 |
| G06 | 実policy Kani、TLC、DB rollback/並行CAS/lost-response fault injection | witness独立運用は仮定。witness同時rollback耐性なし |
| G07 | 固定AS鍵・issuer/audience/sub/grant/scope/cnf、ES256/DPoP検査 | oidc-providerの実HTTPS code/S256 PKCE/DPoP nonce/consentを確認。組織の本番AS配置は別途必要 |
| G08 | 単一HTTPS実装、実TLS接続・不正CA拒否、subject/grant分離 | Linux実CLI HTTPS・二人・resident service鍵・restartを確認。Mac上の実行と本番配置は未実施 |
| G09 | importsなしWasm、fuel/memory制限、実PostgreSQLのrole/TTL/失効試験 | trusted provider/DBはTCB。provider停止中の既存session TTLは未保証 |
| G10 | owner-quarantine永久廃止、再承認、署名付きrelease/config/hash/epoch/期限検査 | DB新DEK／新generation、設定再ラップ、E2E新鍵/versionを試験。独立witnessを失った場合は旧grant再開不可。Mac運用未実施 |
| G11 | 製品と同じconsume/bindings/period/UID/retirement/acceptance/secret splitをKani検証 | 実transaction-controllerのrefinementを追加。型変換・crypto・storage・OSを含む全体refinementと独立reviewは未完了 |
| G12 | 3種署名＋source/binary/config/host/期間＋全条件の検査、負例試験 | 承認者・証跡内容の真実性は信頼仮定。実署名付き受入記録なし |
| G13 | locked build、依存監査、固定tools/images、source/log digest、clean rebuild比較 | Mac ARM64のRust/Swiftクロスビルドを追加。別組織builder/独立レビュー、Mac実OSでの再現は未実施 |

## Kani: 実コードに対する14 harness

`crates/policy`はno_std、I/O/crypto/unsafeを持ちません。Rust 1.91.1で製品をビルドし、Kani 0.66.0付属nightly/CBMCで同じ実コードを検査します。scalar stateに小さい定数範囲を仮定せず、各型の全ビットパターンを対象にします。

1. consumeのaccept/rejectが宣言的allowed仕様と同値で、成功時の回数・sequence・不変fieldが仕様どおり。
2. token/DPoPが有効でもdeviceまたはguardianの一方が欠ければ拒否。
3. 確定後の同一sequenceを拒否。
4. revoked/lockedを拒否。
5. 異なるepochまたはwitness欠如を拒否。
6. 成功時のbudget厳密減少・sequence厳密増加。
7. 実装の1byte XOR分割の復元性と、一方のshareは任意の候補秘密と両立する代数。
8. UID allocatorの算術がroot/AIを選ばず、成功時の次UIDが増加。
9. request_periodがu128の数学的期間仕様と一致し、overflowしない。
10. acceptance_checkは必要な証跡methodを省略できず、softwareをphysicalの代用にできない。
11. bindings_matchは全12項目のrecord equalityと一致。
12. recoveryのretired stateからconsumeが成功しない。
13. 実`authorize_and_commit`＋`ordered_commit`がatomic disclosure仕様と同値で、witness→DB確定後にのみ一回の開示capabilityを返す。
14. 物理試験の除外がG04/G05のphysical method以外を省略できず、software evidenceも必須である。

詳細な対応と残る仮定は[PROOF_CONTRACT.md](PROOF_CONTRACT.md)を参照。

Bindingの検査はgeneric関数をu128/u8にinstantiateしたものです。実サービスはUUID・文字列・Action・IssueSpecの等値性を使い、Grant/Operationからの変換は手動コードです。その等値性、serialization、変換自体をKaniで証明したとはしません。実行試験で全security fieldを改変して拒否を確認します。

5署名flagの走査のみunwind=6でunwinding assertionを検査します。無限ループの任意打切りではありません。XORの証明は乱数の一様性、AEAD／HPKEの計算量的安全性の証明ではありません。Kani/CBMC/Rust変換の健全性はTCBです。到達しないunsupported intrinsicに関する警告もログに残します。

`scripts/check-kernel-mutations.py`は実sourceからguardian・sequence・recipient照合・witness先行処理を除去したコピー、および常に拒否する変更を検証し、対応harnessが反例を出すことを要求します。単なるbuild失敗を成功扱いしません。正規成功の実行試験により全拒否だけで安全性を満たしていないことも確認します。

## TLC: 有限並行モデル

`formal/Vault.tla`: honest要求2個、token/DPoP盗難、deviceOnly、guardianOnly、budget=2。DBロック、witness先行予約、DB commit、開示、失効、crash、過去diskへのrollback、owner-authorized quarantineをモデル化します。commit後〜開示前にも別要求や失効が入れます。

TypeOK、NoUnauthorizedRelease、NoReplay、BoundedRelease、CommitBeforeDisclosureを検査します。復旧追加後の構成は11,754 distinct states、50,461 generated、深さ16。正本は実行ログです。fingerprint衝突確率の評価も残します。

guardian、device、witness、commit-before-releaseの各検査を無効にした4モデルについて、指定不変条件の反例を必須にしています。**これらの非ゼロ終了は期待された検出成功**です。任意人数／無制限状態の帰納証明やliveness証明ではなく、JWT/crypto/SQL詳細は抽象化されています。TLAとRustサービス全体とのsimulation relationは未証明です。

## 実行証跡

`evidence/latest/manifest.json`に今回のコマンド・成否、`commands/*.log`にstdout/stderr、`model/`と`mutations/`に反例を含む結果、`sources.json`に対象source SHA-256、`report.md`に要約を保存します。前のrunは`evidence/archive/`へ保存します。

```sh
python3 scripts/verify.py --with-docker --macos-cross
```

開始／終了時のsource hashを比較し、途中変更があれば成功扱いしません。all-feature clippy/test、Kani、TLC、mutation、実OAuth AS、実PostgreSQL、swtpm、Linux別UID隔離、実CLI deployment、Macクロスビルド、依存監査、release、別targetのclean rebuild、未受入起動の拒否を記録します。未実行の項目はNOT_RUNです。

OS隔離試験はrootless Docker内で実際のLinux UIDを切り替えて行います。TPM鍵は使わず、broker stateの合成データを保護して確認する試験です。Macの試験や物理鍵耐性を示しません。clean rebuildは同一host/compilerで別targetへ再コンパイルしたbyte一致検査であり、独立builderによるsupply-chain保証ではありません。

readinessの成功fixtureは検査器の単体テストに限ります。fake証跡を製品受入として出力しません。実際の受入記録がない現状のreadinessはfalseであり、通常のserve/witness/brokerを拒否します。native運用を実証したとする署名は発行していません。

CI workflowは追加しましたが、GitHub Actionsはまだ実行していません。公開リポジトリへのソース登録は自動承認審査に拒否され、利用者の明示承認を待っています。Mac ARM64向けのRustとSwiftはLinux上でApple SDKを使ってリンクまで実行しました。これはmacOS上の実行証跡ではありません。

## 依存関係

初回監査でcrypto-bigint、SQLite/WAL、RSAの既知報告を検出しました。P-256/HPKEを修正版に更新し、rsa crateを除去してOpenSSL公開鍵暗号化へ置換しました。libsqlite3-sysの依存先をSQLCipher 4.20.0／SQLite 3.54.1へ変更した1行patchをvendor化しています。upstream digestと差分は`vendor/PROVENANCE.json`、検査は`scripts/check-vendor.py`。C実装を独自改変していません。

最新の監査結果とRustSec DB commitはログが正本です。既知報告0件は未知の脆弱性の不存在を意味しません。OpenSSL／kernel／firmware／interpreter／compilerの更新もTCB管理に含まれます。

## 本番trueの判定

物理鍵試験は利用者指定で今回の条件から除外しました。実装にも署名対象Releaseとroot管理policyの両方に明示する条件を追加し、ほかの条件は省略できないことを検証しています。

今回、サービス鍵のstartup-only解錠、実ASプロトコル連携、Macクロスビルド、鍵rotation、実CLIの二人利用とrestartを追加しました。残るのはmacOS上のソフトウェア実行証跡、サービス全体のrefinement、独立レビュー、実配置に対する署名付き受入です。いずれも物理鍵の未接続と同じ理由ではありません。Mac CIは公開登録の承認待ち、別レビューagentは利用許可待ちです。レビューagentを使えても第三者機関の認証とは呼びません。

Kaniが証明した命題、TLCの有限探索、実行試験、仮定に残る部分を混同して本番trueとは記録しません。配置用の三者署名を同じ自己生成鍵で偽造して受入を通すこともしません。
