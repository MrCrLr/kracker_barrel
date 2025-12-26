# Profiling

This folder contains helpers for inspecting `.prof` files produced by cProfile.

## Layout

- `data/` holds `.prof` captures and the trends CSV output.
- `profile_analyzer_single.py` prints a summary for one profile.
- `profile_analyzer_trends.py` aggregates multiple profiles and exports CSV.
- `profile_analyzer_visual.py` plots CSV trends (requires pandas + matplotlib).

## Examples

Latest profile summary:
```bash
python profiling/profile_analyzer_single.py --limit 30
```

Filter to project functions:
```bash
python profiling/profile_analyzer_single.py --filter "kracker|hash_handler" --limit 50
```

Aggregate + export trends:
```bash
python profiling/profile_analyzer_trends.py --dir profiling/data --output profiling/data/profile_analyzer_trends.csv
```

Visualize trends:
```bash
python profiling/profile_analyzer_visual.py --csv profiling/data/profile_analyzer_trends.csv --top 15 --out profiling
```
