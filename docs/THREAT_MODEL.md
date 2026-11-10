# 脅威モデルと必要条件

## 目標と境界

正規ツールへ返した秘密値の転送・echo・悪意ある利用は利用者の除外条件です。一方、Vault鍵、権限を広げたgrant、未承認の復号、回数の再利用、DBからの復号は防御対象です。

トークンとDPoP秘密鍵を同時に盗んだ攻撃者は、OAuthに関しては正規クライアントと区別できません。追加する識別根拠は、別保護領域のdevice／guardianによる、nonce・recipient・対象・実行物・期限まで含む署名です。これらの署名オラクルまで自由に操作できる攻撃者はこの前提を超えます。ブロックチェーン、ZK所有証明も、盗んだ同じwitnessだけで正規者と攻撃者を区別する根拠にはなりません。

## 攻撃能力

| 攻撃 | 実装での扱い | 残る条件 |
|---|---|---|
| OAuthトークン＋DPoP鍵の流出 | device・guardianの独立署名を要求 | 承認UI／署名サービスを攻撃者が代理操作できないこと |
| 通信の観測・差し替え | TLS＋署名＋AEAD、recipient／要求ハッシュへの束縛 | 証明書・issuer・owner公開鍵の登録を信頼 |
| DB・WAL・バックアップと鍵envelopeの流出 | SQLCipher＋ラップ鍵＋E2E暗号 | 非エクスポート鍵とアンロック認証が破られないこと |
| Vault DBの改変・過去への巻き戻し | 独立witnessの版・ハッシュと不一致なら停止 | witness自身も同時に巻き戻されないこと |
| 許可範囲外の操作・別ユーザーのgrant | owner署名、OAuth sub、grant ID、action、resourceの一致を強制 | owner／ASの鍵を信頼 |
| 二重送信・同時送信・クラッシュ | witness→DB確定→開示の順序、使用回数を消費 | SQLiteのロック／fsync、witness CASを信頼 |
| 悪意あるextension入力 | role・TTL・providerを固定、任意SQL不可 | 実際のPostgreSQL権限設定とtrusted issuerを信頼 |
| AI／ツールの依存関係侵害 | grantの実行物ハッシュ／recipient束縛、鍵をHTTPで公開しない | root管理broker／使い捨てUIDを実装、Linux隔離試験済み。Mac実機未検証 |
| PC盗難 | Secure Enclave＋user presence、TPM＋PINを設計 | 物理実機未検証。稼働中でアンロック済みのPC全体を奪われる場合は未解決 |
| サービス／OS／コンパイラの侵害 | TCB侵害として保証外 | 独立guardian、最小権限、更新承認、再現ビルド検証が必要 |

## 信頼する要素

ownerのgrant承認、OAuth ASの署名、deviceとguardianの独立した鍵保護・操作承認、Runner、検証コード、暗号ライブラリ、SQLCipherとOpenSSL等のCコード、カーネル、ハードウェア、時計、乱数、コンパイラ／検証器をTCBに含めます。自前Rustコードの`unsafe_code=forbid`は依存CやOSの安全性を証明しません。

本実装の`device_public_key`と`guardian_public_key`は異なる鍵であることしか検証しません。異なる物理機器、利用者、UID、クラウドアカウントであることを証明するattestationはありません。非エクスポート性もAPI応答と登録運用に依存します。

localとhostedで機構は同一です。localでも独立witnessを必要とします。同じディスクにVaultとwitnessを置き、両者のスナップショットを戻せる配置では、巻き戻し耐性は成立しません。完全オフラインの一台構成で同等の耐性を出すには、TPM NV等による非巻き戻し状態の実装が必要です（未実装）。

## 失効・可用性

線形化点は使用回数を消費する永続コミットです。それより前に確定した失効は要求を拒否します。既にコミットされた処理・返却した秘密を後の失効で取り消すことはできません。

witness成功後にDB確定が失敗すると停止します。過去のバックアップを「最新版」として自動採用しません。owner承認済みの最新checkpointに対するquarantineで旧IDを永久廃止し、新IDに再承認できます。鍵rotationとwitnessを保持するquarantine／再認可は実装済みです。復号鍵喪失時は既存の復旧用保護領域が必要で、復旧鍵がなければデータは復元できません。witnessの同時巻き戻しや最新状態喪失からの権限復活は許しません。時計の逆行に強い期限管理は未実装で、信頼できる時刻を前提にします。

DoS、トラフィック量・DB容量・鍵envelopeの公開鍵fingerprint等のメタデータ漏洩、OSメモリのフォレンジック、アンロック中の物理攻撃は今回の保証に含みません。ゼロ化はベストエフォートで、全ライブラリの複製やswapまでの保証ではありません。
