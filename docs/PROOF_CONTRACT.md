# 機械検証と実装の対応

検証対象は`crates/policy/src/lib.rs`の製品と同じRustコードです。別言語へ書き写したpolicyだけを証明して、製品の証明とする構成ではありません。

## 直接機械検証した命題

`consume(s,r,e)`の成功条件は、全認可証拠・record binding・witnessが成立し、非失効・非ロック、epoch/sequence一致、有効期間内、正の残回数、sequence非overflowであることと同値です。成功後は残回数が1減り、sequenceが1増え、他のfieldを保存します。Kaniでは型の全bit幅に対する入力を用います。

`authorize_and_commit`はこの判定後にだけpersist closureを呼び、その成功後にだけ`Committed<T>`を返します。実adapterのpersistは`ordered_commit`を通り、witness成功後にだけDB commitを呼びます。Kaniの`implementation_transaction_refines_atomic_disclosure_spec`は、任意State/Request/Evidenceと両永続処理の任意成功／失敗に対して、開示が可能なのは許可条件と両成功の積であること、順序と回数を検査します。全拒否するだけの実装もspecと不一致になります。

`Committed`は外からfieldを構築できず、Cloneがなく、releaseで消費します。compile-fail doctestは外部での構築と二重消費がRust compilerに拒否されることを検査します。ただし、公開constructor関数に虚偽Evidenceや虚偽persist closureを渡すtrusted Rustコードまで排除する型ではありません。HTTP callerからそのclosureやEvidenceを与えられないことはadapterの設計境界です。

実`store.rs`ではprotocol検証から得たprivate `Verified`とDB stateを使って`authorize_and_commit`を呼びます。witness予約→DB commit後に返るrecord capabilityのrelease closure内でguardian shareを復号します。実SQL triggerでcommitを失敗させた試験では、復号器呼出しが0で、旧要求が再開できないことを確認します。

このほか、recordの12項目binding、時間区間のoverflow、UID割当、永久廃止、受入method完全性、物理試験の限定除外、1 byte XOR分割の代数を検証します。全harnessと反例はevidence内のログが正本です。

## コンポジションの仮定

1. parser・署名検証・hash・HPKE／AEAD・SQLCipherは指定した意味で動く。
2. `protocol.rs`によるwire fieldからEvidence/Bindingへの変換は正しい。全field改変試験はあるが、この変換と暗号検証を丸ごとKaniへ通した証明ではない。
3. DB transactionのatomicity/durability、witness CAS、独立witnessの非巻き戻し性、OSのUID／メモリ保護、時計、乱数が成立する。
4. compiler、Kani/CBMC、TLC、system runtime、native helper、鍵登録、owner/AS/guardianの管理境界を信頼する。

これらの仮定の下では、盗まれたtoken＋DPoP鍵だけで新しいdevice/guardian承認を作れない攻撃者に対し、policy遷移は追加開示を許可しません。数学的な暗号安全性、OS kernel、署名UIを含む全実装の無条件証明ではありません。

TLCは有限の並行／crash／rollbackモデルを探索し、無許可開示・replay・回数超過・commit前開示の反例がないことを検査します。任意人数の無限状態での帰納証明、TLA全体からRust全体へのsimulation relation、サービス全体のlivenessは証明していません。この残りを完了したとする署名や本番trueの証跡は作りません。
