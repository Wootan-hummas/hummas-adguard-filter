# Hummas AdGuard Filter

AdGuardのカスタムフィルター購読URLとして `filter.txt` を使う。

```text
https://wootan-hummas.github.io/hummas-adguard-filter/filter.txt
```

更新時は `data/sources.json` を編集し、次のコマンドで生成する。

```bash
python3 scripts/build_filter.py --write
```

なんJアンテナ掲載元の確認も行う場合は次を使う。

```bash
python3 scripts/build_filter.py --verify --update-verification-metadata --write
```

`livejupiter2.net` のHTTPS証明書にホスト名不一致が出る場合があるため、必要なら `--insecure-tls` を付ける。
