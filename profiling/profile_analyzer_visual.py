import argparse
from pathlib import Path

def visualize_csv_data(csv_file, top_n, output_dir, show_plots):
    """
    Visualize profiling data trends from a CSV file.

    Args:
        csv_file (str): Path to the CSV file.
    """
    try:
        import pandas as pd
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit("pandas and matplotlib are required for visualization.") from exc

    csv_path = Path(csv_file)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Load the CSV data
    df = pd.read_csv(csv_path)
    
    # Preview the data
    print("### CSV Data Preview ###")
    print(df.head())

    # Group data by function and sum cumulative times across files
    grouped = df.groupby("Function")["Cumulative Time"].sum().sort_values(ascending=False)

    # Bar chart: Top N functions by cumulative time
    top_functions = grouped.head(top_n)
    plt.figure(figsize=(10, 6))
    top_functions.plot(kind="bar")
    plt.title(f"Top {top_n} Functions by Cumulative Time")
    plt.ylabel("Cumulative Time (s)")
    plt.xlabel("Function")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    top_plot = output_path / "top_functions.png"
    plt.savefig(top_plot)
    if show_plots:
        plt.show()
    plt.close()

    # Line plot: Trends for a specific function across files
    function_trends = df[df["Function"] == top_functions.index[0]]
    function_trends = function_trends.sort_values("File")

    plt.figure(figsize=(10, 6))
    plt.plot(function_trends["File"], function_trends["Cumulative Time"], marker="o")
    plt.title(f"Trend of '{top_functions.index[0]}' Across Files")
    plt.ylabel("Cumulative Time (s)")
    plt.xlabel("Profile File")
    plt.xticks(rotation=90)
    plt.tight_layout()
    trend_plot = output_path / f"{top_functions.index[0]}_trend.png"
    plt.savefig(trend_plot)
    if show_plots:
        plt.show()
    plt.close()

    print(f"Visualization complete. Saved plots to '{top_plot}' and '{trend_plot}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualize profiling trends from CSV.")
    parser.add_argument("--csv", type=str, default="profiling/data/profile_analyzer_trends.csv", help="CSV file path")
    parser.add_argument("--top", type=int, default=10, help="Top N functions to plot")
    parser.add_argument("--out", type=str, default="profiling", help="Output directory for plots")
    parser.add_argument("--show", action="store_true", default=False, help="Show plots interactively")
    args = parser.parse_args()

    visualize_csv_data(args.csv, args.top, args.out, args.show)
