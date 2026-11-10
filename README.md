# vault-rs

Rustによる二者承認・E2E暗号の秘密情報管理。最終目標は **本番利用 `production_ready=true`** です。[13の必須受入条件](docs/PRODUCTION_GOAL.md)を固定し、物理鍵の実機試験だけを利用者の指定で除外し、合成データを実機証跡とは扱いません。

**現時点ではゴール未達、本番利用不可です。** 物理鍵試験は対象外です。macOS上での実行、サービス全体のrefinement、独立レビュー、実配置の受入証跡は揃っていません。OAuth code＋S256 PKCE＋DPoPの実AS接続、無人サービス用のresident鍵、DB／E2E／設定鍵のrotation、Linuxでの実CLI運用試験、Mac ARM64へのRust／Swiftクロスビルドを追加しました。署名付き証跡がない本番起動は拒否します。詳細は[保証範囲](docs/ASSURANCE.md)にあります。

## 実装した機構

- OAuth＋DPoPに加え、deviceと独立guardianの要求全体への署名を必須化。tokenとDPoP秘密鍵を同時に盗んでも追加の独立承認が必要です。
- owner署名でsubject・秘密ID／版・操作・実行物と引数・実行インスタンス・受信鍵・期限・回数を固定。root管理brokerが実行物を固定し、witnessで一度限りのUIDを割り当てたツールへ、専用stdinで許可済み秘密値だけを渡します。
- 秘密ごとのDEKを2-of-2に分割し、各shareを別のP-256 HPKE鍵にラップ。返却データもrecipientにHPKE暗号化。Vaultは静的秘密のdevice shareを取得しません。
- SQLCipherでDB／WALを暗号化。DB鍵と発行器設定もハードウェア鍵でラップ。開いているDB鍵・返却済み秘密は実行プロセス内に存在します。
- 独立witnessのCAS→DB確定→開示の順序を強制。巻き戻し／クラッシュはfail closed。owner署名による復旧は古いgrant IDの永久廃止だけを許可します。
- PostgreSQL動的認証情報、限定role／TTL、冪等発行、失効、期限回収。Wasm extensionはhost importなし、メモリ／燃料制限付きで、管理資格情報を受け取りません。
- 標準対象はSecure Enclave搭載MacとTPM 2.0搭載Linux。外部PKCS#11は任意。ソフトウェア鍵への自動フォールバックはありません。
- 署名付きrelease・review・deployment証跡をsource／binary／config／host／有効期間に束縛し、13条件×2OSの必要証跡を検査して本番起動を判定します。

local／hostedは同じHTTPS・暗号・認可実装を使います。単独利用でも独立guardianと巻き戻されないwitnessが必要です。承認用native鍵は対話式です。サービス用resident鍵は起動時にhardware protectorで解錠し、以降のHTTPS／witness処理ではUI／PINを繰り返し要求しません。resident鍵自体の非エクスポート性は主張しません。

## 検証

Linux: Rustup、Cコンパイラ、pkg-config、OpenSSL開発ヘッダ、Python 3、Java 21、Node.js 24、Docker。MacのビルドにはXcode Command Line ToolsとOpenSSLが必要です。

```sh
python3 scripts/restore-vendor.py
bash scripts/prepare-tools.sh
python3 scripts/verify.py --with-docker --macos-cross
```

Kaniで製品と同じpolicyコード、TLCで有限並行モデル、実行試験でHTTPS／暗号／DB／別UID隔離／sandboxを検査します。さらにlocked build、依存監査、別targetへのクリーン再ビルドを行います。[保存した証跡](evidence/latest/report.md)にコマンド・結果・source／log／binaryのSHA-256を記録しています。Dockerを省略した項目はNOT_RUNです。全体の安全性証明や第三者認証ではありません。

```sh
cargo run --locked -p vault-rs -- readiness
cargo run --locked -p vault-rs -- observe --config /absolute/path/config.json
```

証跡なしのreadinessは非ゼロ終了します。通常の`serve`／`witness`／`broker`は`--acceptance`必須です。検証専用の`--verification-run`は本番判定をtrueにせず、serverのbindはloopback限定です。これを本番受入の回避に使わないでください。

## 利用インターフェース

`seal`、`protect-config`、`generate-service-key`、`rotate-storage`、`rewrap-config`、`measure-bundle`、`broker`、`approve`、`serve`、`witness`、`observe`、`readiness`を提供します。owner／guardianの承認は、型を固定したJSONとネイティブ鍵の確認画面／PINを通します。汎用OAuth同意UI・組織管理UIは含みません。

[鍵・OAuth・復旧の運用](docs/OPERATIONS.md)、[brokerと受入](docs/BROKER.md)、[プロトコル](docs/PROTOCOL.md)、[脅威モデル](docs/THREAT_MODEL.md)、[鍵登録と実機検証](docs/HARDWARE.md)、[構成例](examples/)を参照してください。構成例はプレースホルダーであり、そのまま起動できません。テスト用PEMは公開済み合成データです。
