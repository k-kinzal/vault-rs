# 保証範囲と証跡

製品の本番利用判定は `evidence/release.json` の `decision_scope=software_release`、特定配置の判定は実CLI `readiness` の `decision_scope=deployment` です。製品判定にはLinux全試験と実macOS上のソフトウェア試験を、同一sourceに対して必要とします。配置先の署名は自動生成しません。物理鍵実験のみ利用者指定で除外します。

## ゴールと証跡の対応

| ID | 実装・必要証跡 | 保証境界 |
|---|---|---|
| G01 | device/guardian独立署名、共有wire predicateのKani、盗難token/DPoPと各field改変試験 | 署名偽造困難性と登録鍵を信頼 |
| G02 | Mac/Linux別UIDでmemory/FD/file/IPC/直接broker起動を拒否 | kernel/rootはTCB |
| G03 | bundle/引数/instance/recipient束縛、変更不可path、Mac ACL拒否 | system runtimeと管理者更新を信頼 |
| G04 | SE/TPM helper build、swtpm、native profileの誤鍵拒否 | 物理鍵実験は除外。fixtureをhardware証跡にしない |
| G05 | SQLCipher/WAL、2-of-2 E2E、受入済みDB generation pin、差替え前unwrap拒否 | hardware protector、暗号primitive、swap/物理メモリ保護 |
| G06 | Kani controller、TLC並行/crash/rollback、実DB commit失敗 | 独立witness CASと非巻き戻し性 |
| G07 | 実ASのcode/S256 PKCE/DPoP/nonce/subject/期限、共有scope/parser predicate | 本番ASのidentity/consent運用 |
| G08 | 両OS実CLI HTTPS、二人利用、private stdin、再起動・失効 | 配置先TLS/identity登録 |
| G09 | Wasm import/FS/network/fuel/memory制限、実PostgreSQL role/TTL/冪等/失効 | trusted issuer/SQL。停止中の既存DB sessionは期限切れだけで終了しない |
| G10 | DB DEK/設定/E2E rotation、永久廃止、source/binary/config/host/epoch/期限束縛 | 更新時の停止・新世代path・再受入 |
| G11 | 実認可/共有型/実32byte split/commit controllerの機械検証、反例付き変異試験 | PROOF_CONTRACT.mdのprimitive契約。全service simulation theoremではない |
| G12 | 指定鍵署名と完全性、受入snapshot、transitive入力pin、各種負例 | 署名者・ログ出所の信頼。異なる鍵は異なる人間の証明ではない |
| G13 | locked build、依存監査、固定tools/images、両OS clean rebuild、独立agentレビュー | compiler等はTCB。第三者認証とは呼ばない |

## 形式検証

Kaniは製品と同じno_std policyコードをRustの全scalar bit幅で検証します。wire field比較、OAuth/DPoP、challenge、execution、実Request変換、State遷移、永続順序、UID/失効/期間、証跡methodと物理除外、32byte share処理を含みます。scope文法は実装の入力上限256 byte全域です。harness数と成否の正本は `commands/kani.log` です。署名関数やserde/OpenSSL/OSをKaniに渡した証明ではありません。

TLCのbaselineは一つのgrant、4 request identities、budget/challenge/admin/provider attempts各2の有限探索です。拡張モデルのレビュー時探索は1,587,137 distinct states、9,465,906 generated、depth 33でした。再実行ログを正本とし、fingerprint衝突評価も残します。6防御の削除は指定不変条件の反例を必須とし、3到達性試験で正規release・同一issue再送・admin crash後quarantineを確認します。

実Rust sourceの認可検査を削除するmutationも、対応harnessの `VERIFICATION:- FAILED` を必要とします。コンパイル失敗は検出成功として数えません。暗号学的安全性、任意人数の無限状態、全サービスのlivenessや未知脆弱性の不存在を証明したとは扱いません。

## 実行と統合

```sh
python3 scripts/restore-vendor.py
bash scripts/prepare-tools.sh
python3 scripts/verify.py --with-docker --macos-cross
python3 scripts/release-evidence.py evaluate \
  --linux evidence/latest --macos evidence/macos --output evidence/release.json
```

Linux runは開始/終了source不変、format/clippy/test、実OAuth AS、Kani/TLC/mutation、実PostgreSQL、swtpm、別UID隔離、実CLI deployment、監査、release/clean rebuildを記録します。MacはGitHub `macos-15` runner上でunit/integration、OAuth、OS隔離とACL、実CLI二人利用/再起動/失効、Swift helper build、clean rebuildを行います。Mac cross buildだけではMac runtime evidenceを満たしません。

各manifestはsource一覧、source fingerprint、binary/log SHA-256を持ちます。統合validatorは両OSのsource一致、全必要検査、ログdigest、レビュー結果を照合します。これはレビューされた実行ログからの条件付き判定であり、hashや署名がログの真実性まで証明するものではありません。`readiness`の成功fixtureは検査器の試験で、実配置の受入にexportしません。

## レビューと依存

[REVIEW.md](REVIEW.md)に別agentの所見・修正・残る仮定を保存します。自動化された独立コンテキストのレビューであり、独立組織や人間の認証ではありません。Mac CIで見つかったTLS証明書生成差、DB parent alias/NOFOLLOWの差も実行で修正しています。

初回監査のcrypto-bigint/SQLite/RSA報告に対応し、P-256/HPKEを更新し、RSA private crateを製品から除去しました。libsqlite3-sysはupstream archive digestとSQLCipher/SQLite依存指定の1行patchを検証します。Cコードの独自改変はありません。最新RustSec DB commitと監査結果は実行ログが正本です。compiler/kernel/OpenSSL/helper等の更新も新しい配布物と配置受入の対象です。
