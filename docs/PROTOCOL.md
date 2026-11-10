# v1プロトコル

## 静的シークレット

1. クライアントでランダム256bit DEK `K` と独立256bit `A` を生成し、`B = K XOR A` とする。
2. `vault/resource/version` をAADとしてXChaCha20-Poly1305で秘密を暗号化する。`A`はdevice公開鍵、`B`はguardian公開鍵でラップする。
3. ownerがレコードハッシュ、subject、action、resource/version、epoch、期間、uses、DPoP JWK thumbprint、二つの署名公開鍵、recipient、instance、artifact_hashを含むgrantに署名する。
4. `/v1/install` はowner署名を検証して新しいIDだけを登録する。`/v1/challenge` は有効なgrantに対し次のsequenceと256bit nonceを返す。challenge発行自体は秘密を開示しない。期限内のchallengeは再取得しても同じ。
5. クライアントがtoken hash、grant hash、nonceを含むOperationを作成する。deviceとguardianが異なるdomainで同じOperationに署名する。OAuth/DPoPも同時に送る。
6. `/v1/release` がすべての署名と束縛を検証し、witness CAS→SQLCipherトランザクションを確定して回数を消費した後、guardian側シェアだけを復号する。
7. guardianシェアをrecipientのX25519 HPKE鍵に暗号化する。client SDKは要求とレコードを再検証し、deviceのシェアと合成してローカル復号する。

静的シークレットの平文とdeviceシェアをVaultへ送るAPIはありません。ServerのDB暗号化鍵はこのDEKとは別で、起動時にハードウェアでアンラップしSQLCipherへ渡します。DB鍵が漏れても二つのシェア保護は残ります。

## 暗号と符号化

- 署名はES256、公開鍵はcompressed SEC1 33bytesのbase64url、署名は固定64bytes。JSONの型・フィールド順をRustのstruct定義で固定し、unknown fieldsを拒否する。AccessClaimsのみ追加AS claimを許可する。重複した既知fieldはserdeが拒否する。
- 署名対象は `vault-rs/v1/<domain>\0 || serde_json(struct)`。JSON全般のJCSではない。相互運用実装は型のフィールド順、null、整数、UUID、base64url表現を一致させる必要がある。
- P-256鍵ラップはRFC9180 DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305 base mode、sequence=0のみ。labelはinfoとAADの両方に入る。HPKE senderはライブラリ、非エクスポートECDH用receiver glueは`external_kem.rs`。公式vector＋upstreamとの相互運用試験あり。
- オプションRSA鍵ラップはRSA-3072～4096、e=65537、OAEP-SHA256/MGF1-SHA256。レコードcontext・シェアの役割をlabelに束縛。productionの秘密RSA演算はPKCS#11だけ。
- レスポンスHPKEはX25519/HKDF-SHA256/ChaCha20Poly1305、info=`vault-rs/v1/response`、AAD=Operation hash。
- すべての公開鍵を使う場所で型・サイズ／curveを検証。秘密／シェアのログ出力はしない。`ReleaseRequest`はtokenの誤ログを避けるためDebugを実装しない。

## OAuth / DPoP profile

これはOAuth Resource Serverの厳格なprofileであり、新しいAuthorization Serverではない。brokerはauthorization-code/S256 PKCE/DPoPを実装する。同意UIは接続先ASに委ねる。issuer鍵は固定し、自動JWKS rotationを行わず配置更新で切り替える。

ASはES256 `typ=at+jwt`、固定issuer署名鍵、`iss,aud,sub,nbf,exp,scope,grant_id,cnf.jkt`を発行する。scopeは`secret:read`または`secret:issue`で、owner grantとの積集合が実効権限になる。scopeだけで秘密を選べない。

DPoPはRFC9449形式の`typ=dpop+jwt`、P-256 public JWK、`htm,htu,iat,jti,ath,nonce`を検証する。`htu`は設定されたHTTPS origin＋固定endpointから計算し、Host/X-Forwarded-*を信用しない。要求期限は30秒以下、iatは未来不可、nonceとsequenceは一度だけ消費する。HTTP Authorization/DPoPヘッダではなく、署名付きリクエストenvelopeのJSON fieldとして運ぶ独自profileなので一般的middlewareに無改造で接続できるとは扱わない。

## 動的発行

`action=issue` のowner grantとOperationに`IssueSpec{provider,role,ttl_seconds}`を入れる。同じ認証・署名・回数消費を通り、永続outboxからのみ`CommittedIssue`を構築する。この型は外部から生成／Deserializeできない。trusted PostgresIssuerは接続先・role policyをローカル設定で固定する。

DBトランザクションでユーザー作成・権限付与と暗号化したreceiptの保存を同時に行う。要求ハッシュで冪等化し、同じpending要求だけを有効期限内に再試行できる。完了後のリプレイは拒否する。応答を失った場合の完了receipt再取得APIはない。未完了・期限切れoutboxは自動で回数を戻さず、ownerによる失効／新grantが必要。

生成器と対象PostgreSQLは発行するpasswordを一時的に知る。動的シークレットでは生成器自体がE2Eの端点であり、「生成器さえ秘密を知らない」ことは保証しない。provider接続設定は`protect-config`で暗号化し、起動時だけハードウェアで開く。

ユーザーは`NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`、登録されたroleの権限のみ。固定roleが強すぎれば発行ユーザーも強くなるため、実権限の試験が必要。失効はNOLOGIN、既存session termination、DROP ROLE、tombstone。TTLはDBのVALID UNTILとexpiry workerで処理する。worker停止中も新規ログインは期限切れになるが、既存セッションの強制終了はworkerの生存に依存する。

Wasm proposal extensionは`wasmi`で実行します。host import/WASIなし、memory 64KiB、fuel 100000、module 128KiB、JSON 4096bytesまで。`memory`と`propose(i32 pointer,i32 length)->i64`をexportし、戻り値の上位32bitは出力pointer、下位32bitはlengthです。出力IssueSpecは署名された入力と一致しなければ拒否します。管理用資格情報・filesystem・networkをextensionへ渡しません。新しいproviderの管理操作はtrusted adapterとして別途レビューが必要です。

## 実行と復旧

brokerは他の認可とguardian署名を確認してからdevice署名を要求します。期限の再確認をHTTP応答前に行い、hardware/DB/witness待機中に期限を超えた応答を返しません。動的発行で期限を超えた場合は発行済みleaseの失効を試みます。provider停止時の既存sessionについては前述の制限があります。

`/v1/checkpoint`はowner署名済みGrantに対して独立witness値を返します。owner-quarantine署名された`{vault,grant,expected}`を`/v1/quarantine`へ送ると、そのcheckpointに対するCASが成功した場合だけIDを永久廃止します。残り回数の再付与・witnessの巻き戻しは行いません。
