[English](README.en.md)

# r2-copilot

`r2-copilot` は、強力なリバースエンジニアリングフレームワークである [radare2](https://github.com/radare/radare2) のための Multi-Agent Collaboration Protocol (MCP) サーバーです。

このリポジトリはサードパーティーツールになります。オフィシャルのmcpツールは以下になります。
* **r2mcp** - the [official radare2 mcp](https://github.com/radareorg/radare2-mcp)
* **r2ai** - the [official r2ai](https://github.com/radareorg/r2ai)

## インストール
※ r2pmに追加してもらえました！`r2pm -Uci r2-copilot`でインストール可能です。

## セルフビルドする場合

1.  リポジトリのクローン
```bash
git clone https://github.com/your-repo/r2-copilot.git
cd r2-copilot
```

2.  依存関係のインストール
プロジェクトでは `uv` を使用して依存関係を管理しています。

```bash
uv sync
```

##  radare2のインストール
`r2pipe` が正しく動作するためには、`radare2` がシステムにインストールされている必要があります。

```bash
mkdir -p ~/.local/src/
cd ~/.local/src/
git clone https://github.com/radareorg/radare2 --depth 1
radare2/sys/install.sh
```

windowsの場合、ビルド済みバイナリをダウンロードしてきてPATHを通す方が早いです。

see. https://github.com/radareorg/radare2

## 使用方法

サーバーを起動するには、次のコマンドを実行します。

```bash
./start.sh
```

これにより、標準入出力（stdio）を介して通信する MCP サーバーが起動します。
サーバーは、クライアントからのリクエストを待ち受け、radare2 のコマンドを実行し、結果を返します。

gemini-cliで利用するには、 `~/.gemini/settings.json` を以下の通りに追記してください。

```json
{
  /*
      ...
  */
  "mcpServers": {
    /*
        ...
    */
    "r2-copilot": {
      "command": "r2pm",
      "args": ["-r", "r2mcp"]
      /* セルフビルドの場合で、uv使ってない人はこれ
      "command": "/path/to/r2-copilot/start.sh"
      /* 
      /* uvを使ってる場合はこっちの方がパフォーマンス出ると思います  
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/r2-copilot",
        "r2copilot"
      ]
      */
  }
}
```

## 解析ワークフロー

一般的なバイナリ解析は、以下のステップで進めることが推奨されます。
なお、gemini-cli等を利用する場合は具体的なコマンドを暗記する必要はなく、自然減での入力が推奨されます。

1. セッションの開始

まず、解析対象のファイルに対してradare2セッションを開始します。これにより、以降の操作で参照するセッションIDが発行されます。

コマンド:
`create_session(file_path='<ファイルへの絶対パス>')`

例:

 ### /home/kali/ctf/iris/sqlate/vuln を解析する場合
 `print(default_api.create_session(file_path='/home/kali/ctf/iris/sqlate/vuln'))`
> Note: このコマンドの応答に含まれる session_id は、後続の全てのコマンドで必要になります。

2. 初期静的解析（情報収集）

セッションが開始されたら、バイナリの基本的な情報を収集します。これらのコマンドは並行して実行可能です。

 * バイナリの基本情報を取得:
    `get_binary_info(session_id='<session_id>')`
    (アーキテクチャ、ビット数、ファイル形式などを確認します)

 * セキュリティ機構の確認:
    `check_security(session_id='<session_id>')`
    (NX, PIE, Canaryなどの緩和機能が有効かを確認します)

 * 文字列のリストアップ:
    `get_strings(session_id='<session_id>')`
    (バイナリに埋め込まれた文字列を抽出し、プログラムの機能や目的を推測する手がかりを探します)

 * インポート関数のリストアップ:
    `get_imports(session_id='<session_id>')`
    (外部ライブラリからどの関数を呼び出しているかを確認します。systemやstrcpyのような危険な関数の有無は重要な指標です)

3. 詳細解析

次に、radare2の強力な自動解析機能を実行します。これにより、関数、基本ブロック、コードの相互参照などが特定されます。

コマンド:
`analyze_all(session_id='<session_id>')`

> Note: この処理は、バイナリのサイズによっては時間がかかる場合があります。

4. 関数の調査

自動解析が完了したら、特定された関数をリストアップし、プログラムの全体像を把握します。

 * 関数一覧の表示:
    `list_functions(session_id='<session_id>')`

 * 特定の関数の逆アセンブル:
    `disassemble_function(session_id='<session_id>', address='<関数名 or アドレス>')`
    (例えば、プログラムの起点であるmain関数を調べるには address='sym.main' を指定します)

5. 高度な操作（生コマンドの実行）

より複雑な調査や、特定のツールが期待通りに動作しない場合、`execute_command` を使用してradare2の任意のコマンドを直接実行できます。

コマンド:
`execute_command(session_id='<session_id>', command='<radare2コマンド>')`

 ```python
 # "login" という文字列を名前に含む関数を検索する
 print(default_api.execute_command(command='afl | grep login', session_id='...'))
 ```

## API リファレンス

サーバーは、以下のツールを公開しており、それぞれが特定の radare2 の機能に対応しています。

### セッション管理

-   `create_session`: 新しい radare2 セッションを開始します。
-   `list_sessions`: アクティブなセッションを一覧表示します。
-   `close_session`: セッションを閉じます。
-   `switch_session`: 現在のセッションを切り替えます。

### 解析

-   `analyze_all`: バイナリ全体を解析します (`aa`)。
-   `analyze_function`: 特定のアドレスの関数を解析します (`af`)。
-   `list_functions`: 解析された関数を一覧表示します (`afl`)。
-   `get_function_info`: 関数の詳細情報を取得します (`afi`)。
-   `get_xrefs_to`: 特定のアドレスへのクロスリファレンスを取得します (`axt`)。
-   `get_xrefs_from`: 特定のアドレスからのクロスリファレンスを取得します (`axf`)。

### バイナリ情報

-   `get_binary_info`: バイナリに関する包括的な情報を取得します (`iI`)。
-   `get_sections`: セクションを一覧表示します (`iS`)。
-   `get_symbols`: シンボルを一覧表示します (`is`)。
-   `get_strings`: 文字列を一覧表示します (`iz`, `izz`)。
-   `get_imports`: インポートされた関数を一覧表示します (`ii`)。
-   `get_entrypoint`: エントリポイントを取得します (`ie`)。
-   `check_security`: セキュリティ機能（NX, PIE など）を確認します。

### ディスアセンブリ

-   `disassemble`: 命令をディスアセンブルします (`pd`)。
-   `disassemble_function`: 関数全体をディスアセンブルします (`pdf`)。
-   `print_hex`: 16進ダンプを表示します (`px`)。
-   `print_string`: アドレスにある文字列を表示します (`psz`)。

### ナビゲーション

-   `seek`: 特定のアドレスに移動します (`s`)。
-   `seek_relative`: 相対的に移動します。
-   `get_current_address`: 現在のアドレスを取得します。
-   `set_block_size`: ブロックサイズを設定します (`b`)。

### 検索

-   `search_bytes`: バイトパターンを検索します (`/x`)。
-   `search_string`: 文字列を検索します (`/`)。
-   `search_rop_gadgets`: ROP ガジェットを検索します (`/R`)。

### 書き込み

-   `write_hex`: 16進数値を書き込みます (`wx`)。
-   `write_assembly`: アセンブリ命令を書き込みます (`wa`)。
-   `write_nop`: NOP 命令を書き込みます。

### デバッガ

-   `continue_execution`: プログラムの実行を継続します (`dc`)。
-   `step_into`: ステップイン実行します (`ds`)。
-   `step_over`: ステップオーバー実行します (`dso`)。
-   `set_breakpoint`: ブレークポイントを設定します (`db`)。
-   `list_breakpoints`: ブレークポイントを一覧表示します。
-   `get_registers`: レジスタの値を取得します (`dr`)。
-   `set_register`: レジスタの値を設定します。

### フラグ

-   `list_flags`: フラグ（ラベル）を一覧表示します (`f`)。
-   `create_flag`: フラグを作成します。

### 設定

-   `get_config`: 設定値を取得します (`e`)。
-   `set_config`: 設定値を設定します。
-   `execute_command`:生の radare2 コマンドを実行します。
