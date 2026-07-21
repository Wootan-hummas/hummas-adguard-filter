# Hummas AdGuard Filter

個人用のAdGuard購読フィルター。

購読URL:

```text
https://wootan-hummas.github.io/hummas-adguard-filter/filter.txt
```

## 更新

```bash
python3 scripts/build_filter.py --verify --update-verification-metadata --write
```

`data/sources.json` を正本として、`docs/filter.txt` を生成する。
