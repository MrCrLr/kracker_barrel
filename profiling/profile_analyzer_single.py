import argparse
from pathlib import Path
import pstats
import re


def find_latest_profile(prof_dir):
    profiles = sorted(Path(prof_dir).glob("*.prof"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not profiles:
        raise FileNotFoundError(f"No .prof files found in {prof_dir}")
    return profiles[0]


def main():
    parser = argparse.ArgumentParser(description="Inspect a single .prof file.")
    parser.add_argument("--file", type=str, default=None, help="Path to .prof file (default: latest in profiling/)")
    parser.add_argument("--dir", type=str, default="profiling/data", help="Directory to search for .prof files")
    parser.add_argument("--sort", type=str, default="cumulative", help="Sort key (e.g., cumulative, time, calls)")
    parser.add_argument("--limit", type=int, default=20, help="Number of rows to display")
    parser.add_argument("--filter", type=str, default=None, help="Regex to filter function names")
    args = parser.parse_args()

    prof_file = Path(args.file) if args.file else find_latest_profile(args.dir)
    stats = pstats.Stats(str(prof_file))
    stats.strip_dirs()
    stats.sort_stats(args.sort)
    if args.filter:
        stats.print_stats(re.compile(args.filter), args.limit)
    else:
        stats.print_stats(args.limit)


if __name__ == "__main__":
    main()
