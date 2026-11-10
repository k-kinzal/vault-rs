# 機械検証と実装の対応

証明対象は製品が直接使う `crates/policy/src/lib.rs` と `wire.rs` です。暗号・OS・DBの原始機能について下記の契約を置き、認可判定・field対応・開示順序を検証します。検証した命題、有限探索、実行試験、信頼する原始機能を区別します。

## 直接検証する実コード

- `consume` の成功条件は、全認可証拠、record binding、witness、非失効・非ロック、epoch/sequence、有効期間、残回数、非overflowと同値。成功後は残回数が1減り、sequenceが1増え、他のfieldを保存します。State/Requestの全bit幅を検査します。
- `authorize_and_commit` は認可後だけpersistを呼び、その成功後だけ `Committed<T>` を返します。`ordered_commit` はwitness成功後だけDB commitを呼びます。任意のstate・request・証拠・両永続処理の成功／失敗に対し、開示可能性、実行順、回数が宣言的仕様に一致します。常に拒否するだけの変更も検出します。
- Grant/Operation/Challenge/Trust/RecordContext/AccessClaims/DpopClaimsは実サービスと証明で型定義を共有します。owner、record、challenge、実行物・受信鍵・instance、OAuth subject/audience/grant/scope/期限、DPoP key/nonce/target/method/token hash/時刻を実fieldから直接比較します。手動で作ったBindingへの変換を仮定しません。
- `Operation::request` は実際のepoch/sequence/not_before/expires/nowを直接検証します。DB LedgerはpolicyのStateをそのまま持ち、返されたState全体を保存します。
- ScopeSetは256 byte以内のRFC6749 ASCII scope文法を解釈し、認識する完全なtokenだけに権限を与えます。grammar/read/issueを独立したtrie仕様と比較し、256 byte全域の任意入力と全長を扱います。未知scopeは権限を与えません。
- 要求期限はgrant・challenge・実際の署名済みaccess token・最大30秒の最小値。device unwrap後とworkload起動直前にも現在時刻で確認します。
- 実32 byteの `split32` / `join32` の索引を含む全処理について復元性と任意候補秘密との両立を確認します。乱数の一様性や暗号方式そのものの安全性はこの代数の結論ではありません。
- UID割当、永久廃止、時間区間のoverflow、受入method完全性、G04/G05だけの物理試験除外を検証します。

等値比較のgeneric証明はu128等でinstantiateします。UUID/String/IssueSpec等のEq実装は等値関係として振る舞う契約です。JSONからその型を構成するserde全体を証明したとは主張しません。Kani/CBMCとRust変換の健全性は信頼基盤です。

`Committed` は公開field・Clone・Deserializeを持たず、releaseで消費します。外部構築と二重消費のcompile-fail試験があります。trusted Rust callerが虚偽のEvidenceやpersist closureを与えることを型だけで防ぐものではありません。HTTP入力からその値やclosureを作れず、全開示経路がprotocol検証とcontrollerを通ることはソースレビューとadapter fault試験で確認します。

## 有限状態モデル

TLCは一つの既に登録されたgrant、4 request identities、使用回数2、challenge発行2、管理操作2、同じ動的発行への試行2を探索します。challenge再利用／交換、nonce、witness予約とDB commitの分離、並行要求、途中crash、DBの過去世代復元、失効／quarantineの途中crash、pending発行の再試行と完了を含みます。

TypeOK、NoUnauthorizedRelease、NoReplay、BoundedRelease、CommitBeforeDisclosure、OneCredentialPerOperationを確認します。同じ動的leaseの再送は許し、異なる操作のsequence再利用は拒否する仕様です。device/guardian/witness/nonce/commit順序/idempotenceを弱めた6条件は名前を指定した反例を必要とします。正規read、同一issueの二回答、admin予約後crashからのquarantine到達も確認し、全拒否による空虚な成功を避けます。

モデルと実装の対応は [REVIEW.md](REVIEW.md) にあります。TLCは有限探索とfingerprintを使い、無限状態の帰納証明、TLA全体からサービス全体へのsimulation theorem、liveness証明ではありません。PostgreSQLのidempotenceはSQL transaction/advisory lockの契約であり、モデルだけでPostgreSQLを証明していません。

## 原始機能の契約

1. 登録した鍵に対する署名の偽造困難性、HPKE/AEADの機密性と完全性、hashの衝突困難性、独立で予測できない乱数。
2. parserが指定形式のfield意味を保存すること。SQLCipher暗号とメモリ処理、SQLiteのatomic/durable/serialized transaction、PostgreSQLの権限とtransaction契約。
3. witness CASが線形化可能で、Vault DBとは独立に永続化され、攻撃者が両者を同時に巻き戻せないこと。
4. OSのUID/FD/process/memory/ACL/ファイル保護、native helperと鍵登録、信頼できる新しい時計。root、OS kernel、必要な承認domainの全てが攻撃者に支配されていないこと。
5. 管理者は受入済みのhelper・provider設定・CA・extension等を稼働中に上書きしないこと。更新はサービスを停止し、新しい世代のpath・設定を測定し再承認してから行います。DB envelopeはこれに加え、受入時のdigestを実際に読むbyte列に照合してからunwrapします。
6. compiler、Kani/CBMC、TLC、system runtime、検証実行者とログの出所。署名は異なる鍵を示しますが、異なる人間・管理domainやログ内容の真実性を自動証明しません。

これらの条件の下で、token＋DPoP鍵とAI/tool accountの任意コード実行を得ても、独立device/guardian承認を作れない攻撃者に追加の静的秘密開示を許しません。正規に渡した秘密値は利用者指定の除外です。動的秘密の発行器はその値を一時的に知るtrusted issuerです。物理鍵実験は利用者指定で除外し、非エクスポート性を実験済みとは記録しません。
