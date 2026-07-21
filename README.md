# なんJ系AdGuardブロックフィルター

なんJアンテナ掲載元と手動追加サイトを対象にしたAdGuard用購読フィルター。

購読URL:

```text
https://wootan-hummas.github.io/nanj-adguard-filter/nanj-filter.txt
```

## 更新

```bash
python3 scripts/build_nanj_filter.py --verify --update-verification-metadata --write
```

`data/nanj_filter_sources.json` を正本として、`docs/nanj-filter.txt` を生成する。
