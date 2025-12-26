import argparse
import csv
from pathlib import Path
import pstats
import re


def process_profile_file(file_path, sort_key, limit, filter_regex):
    """
    Process and display profiling data for a single file.

    Args:
        file_path (str): Path to the .prof file.
    """
    print(f"Processing file: {file_path}")
    stats = pstats.Stats(str(file_path))
    stats.strip_dirs()
    stats.sort_stats(sort_key)
    if filter_regex:
        stats.print_stats(filter_regex, limit)
    else:
        stats.print_stats(limit)


def aggregate_profile_data(prof_dir):
    """
    Aggregate profiling data from multiple .prof files.

    Args:
        prof_dir (str): Directory containing .prof files.

    Returns:
        pstats.Stats: Aggregated profiling statistics.
    """
    aggregated_stats = None
    prof_files = [p for p in Path(prof_dir).glob("*.prof")]

    for prof_file in prof_files:
        try:
            if aggregated_stats is None:
                aggregated_stats = pstats.Stats(str(prof_file))
            else:
                aggregated_stats.add(str(prof_file))
        except Exception as e:
            print(f"Error processing {prof_file.name}: {e}")

    return aggregated_stats


def export_profile_trends(prof_dir, output_csv, sort_key, limit, filter_regex):
    """
    Export profiling trends to a CSV file.

    Args:
        prof_dir (str): Directory containing .prof files.
        output_csv (str): Path to the output CSV file.
    """
    prof_files = sorted(Path(prof_dir).glob("*.prof"))

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["File", "Function", "Cumulative Time", "Total Time", "Calls"])

        for prof_file in prof_files:
            try:
                stats = pstats.Stats(str(prof_file))
                stats.strip_dirs()
                stats.sort_stats(sort_key)

                items = list(stats.stats.items())
                if filter_regex:
                    items = [(func, data) for func, data in items if filter_regex.search(str(func))]
                items.sort(key=lambda item: item[1][3], reverse=True)
                for func, (cc, nc, tt, ct, callers) in items[:limit]:
                    writer.writerow([prof_file.name, func, ct, tt, nc])
            except Exception as e:
                print(f"Error processing {prof_file.name}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aggregate and export profiling trends.")
    parser.add_argument("--dir", type=str, default="profiling/data", help="Directory containing .prof files")
    parser.add_argument("--output", type=str, default="profiling/data/profile_analyzer_trends.csv", help="CSV output path")
    parser.add_argument("--sort", type=str, default="cumulative", help="Sort key (e.g., cumulative, time, calls)")
    parser.add_argument("--limit", type=int, default=20, help="Top N functions to export per file")
    parser.add_argument("--filter", type=str, default=None, help="Regex to filter function names")
    parser.add_argument("--print", action="store_true", default=False, help="Print per-file summaries")
    args = parser.parse_args()

    filter_regex = re.compile(args.filter) if args.filter else None

    if args.print:
        print("### Processing Individual Files ###")
        for prof_file in Path(args.dir).glob("*.prof"):
            process_profile_file(prof_file, args.sort, args.limit, filter_regex)

    print("\n### Aggregating Data Across Files ###")
    aggregated_stats = aggregate_profile_data(args.dir)

    if aggregated_stats:
        aggregated_stats.strip_dirs()
        aggregated_stats.sort_stats(args.sort)
        print("\n### Aggregated Statistics ###")
        if filter_regex:
            aggregated_stats.print_stats(filter_regex, args.limit)
        else:
            aggregated_stats.print_stats(args.limit)

    print("\n### Exporting Profile Trends to CSV ###")
    export_profile_trends(args.dir, args.output, args.sort, args.limit, filter_regex)
    print(f"Trends exported to {args.output}")
