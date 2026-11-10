# 本番利用のゴール v2（物理鍵試験の明示除外）

最終目標は `production_ready=true` であり、試作の完成ではない。以下は利用者の要求を維持した受入条件である。利用者が「物理鍵は検証できませんがそれ以外は達成」と指定したため、G04/G05の物理鍵実験のみ対象外とする。これは非エクスポート性を実験で証明したという意味ではない。OS上のソフトウェア試験、形式検証、独立レビューは除外しない。mockを実機と扱う変更、期待値をtrueにするだけの変更は達成としない。

## 対象

macOS Secure Enclave搭載機とLinux TPM 2.0搭載機。外部PKCS#11は任意。保護装置がない機器で同等の非エクスポート性を主張しない。local／hostedは同一プロトコル・実装・認可とし、ネットワーク到達範囲と人数だけを変える。単独利用でも独立した承認側と巻き戻されないwitnessが必要。

AIは自身のOSアカウントで任意コード・デバッガを実行でき、OAuth tokenとDPoP秘密鍵を入手できるものとする。開発するツール／extensionの依存物が悪意を持つ場合、DB/WAL/バックアップ流出、紛失PCへのオフライン攻撃を含む。正規に返却した秘密値をツールが転送することは、利用者が明示した除外条件とする。

OSカーネル、保護装置の暗号実装、ownerの承認端点、独立guardianまで全て攻撃者が支配した場合に正規利用者と区別できるという主張はしない。形式的な保証はこのTCBと暗号の標準仮定を明示した条件付きの主張である。

## 必須の受入条件

| ID | 条件 | 必要な証跡 |
|---|---|---|
| G01 | token＋DPoP鍵漏洩で追加アクセス不可 | 署名検証・全field束縛・認可遷移の対応、反例付き負例試験 |
| G02 | AIからbroker鍵、復号鍵、受信鍵を読めない | Mac/Linuxで別UIDからのmemory/FD/IPC/設定/実行物差替え攻撃試験 |
| G03 | owner承認済み実行物と引数だけを実行 | ハッシュ束縛、書換え競合、symlink、環境注入、別プロセスによる要求偽装試験 |
| G04 | 鍵が持出し不能で、盗難機で無承認利用不可 | hardware契約・helperビルド・誤認証／別鍵拒否のソフトウェア試験。物理デバイス実験は明示除外 |
| G05 | DBとWALから秘密／DB鍵を回収できない | 暗号化DB、鍵envelope、片側shareだけでの復号拒否、protector接続試験。物理デバイス実験は明示除外 |
| G06 | 回数、失効、巻き戻し、並行性を守る | Kani、状態機械モデル、実DB fault injection、独立witnessの運用試験 |
| G07 | OAuthの許可範囲を拡大できない | 実ASを含む認可・期限・subject・audience・DPoP・別tenant拒否試験 |
| G08 | 同じ機構でlocal/hosted・単独/複数利用 | Mac/Linuxの実HTTPSによる複数tenant E2E試験 |
| G09 | extensionが発行器の管理権限を得ない | import/FS/network/fuel/memoryの制限試験、固定role/TTL、SQL権限の実DB試験 |
| G10 | 更新・再起動・復旧で権限が復活しない | 署名付きrelease、artifact/config束縛、古い証跡拒否、復旧と鍵rotationの実演 |
| G11 | 形式仕様とsecurity critical実装が対応する | 実認可・binding・broker/release gateの直接機械検証、抽象化境界、未証明の依存の一覧 |
| G12 | 本番判定が偽造・古いログ・自己申告だけで通らない | 指定承認鍵の署名、source/binary/config/環境束縛、証跡期限、全条件の完全性、負例試験 |
| G13 | リリースを再現して保守できる | locked build、依存監査、固定tool/image、全ログとdigest、独立したreviewの記録 |

Mac/Linux双方の必要条件が満たされ、製品と配置先を識別する証跡が揃った時にのみ、本タスクの総合ゴール達成とする。個別のチェック関数がsynthetic fixtureに対してtrueを返すことや、LinuxだけのPASSを総合達成とは扱わない。

## 現在確認できる実行環境

2026-11-10時点で実行済みなのはLinuxクラウド環境と、そのrootless Docker内の独立UID試験。Mac ARM64用Rust本体とSwift helperはApple SDKでクロスビルド済み。`/dev/tpm0`、`/dev/tpmrm0`は存在せず、Mac用接続先・実機runner・認証情報は登録されていない。GitHubコネクタは利用可能で空リポジトリと作業branchを初期化したが、公開ソース登録は自動承認審査に拒否され、利用者の明示承認待ちのためActionsは実行していない。存在しない検証結果を証跡へ記載しない。

## 除外の改ざん防止

`Release.physical_tests_excluded=true`をrelease署名に含め、root管理`AuthorityPolicy.allow_physical_test_exclusion=true`と両方が一致するときだけG04/G05のphysical methodをsoftware methodに置換できる。既定値はfalse。G02のOS隔離やG11/G13の証跡は省略できない。この条件をKaniの全値域検査と署名検証の負例で確認する。

ゴールの定義と、ゴールを達成した証拠は別の成果物である。受入基準を定義した事実だけで本番利用を許可しない。
