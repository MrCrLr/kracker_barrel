import argparse
from pathlib import Path
import sys
import yaml


def load_config(config_file=Path(__file__).parent.parent / "config.yaml"):
    """
    Load configuration options from a YAML file.
    """
    with config_file.open("r") as file:
        return yaml.safe_load(file)


def load_args(config=None):
    """
    Parse command-line arguments, optionally overriding with config.
    """
    parser = argparse.ArgumentParser(
        description="Kracker Barrel - Password Hash Cracker",
    )

    # Mutually exclusive group for operation modes
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        "-d", "--dict",
        action="store_const",
        const="dict",
        dest="operation",
        help="Dictionary attack mode."
    )
    operation_group.add_argument(
        "-b", "--brut",
        action="store_const",
        const="brut",
        dest="operation",
        help="Brute-force attack mode."
    )
    operation_group.add_argument(
        "-m", "--mask",
        action="store_const",
        const="mask",
        dest="operation",
        help="Mask-based attack mode."
    )
    operation_group.add_argument(
        "-r", "--rule",
        action="store_const",
        const="rule",
        dest="operation",
        help="Rule-based attack mode."
    )

    # Common arguments
    parser.add_argument(
        "target_file",
        help="Enter the hashed password file to crack."
    )
    parser.add_argument(
        "password_list",
        nargs="?",
        help="Enter the file name for dictionary comparison (dict/rule modes)."
    )
    parser.add_argument(
        "rules_file",
        nargs="?",
        help="Enter the rules file for rule-based attack (rule mode only)."
    )

    # Arguments specific to brute-force attack
    parser.add_argument(
        "--charset",
        type=str,
        default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        help="Character set for brute-force attack (default: alphanumeric)."
    )
    parser.add_argument(
        "--min",
        type=int,
        default=1,
        help="Minimum password length for brute-force attack (default: 1)."
    )
    parser.add_argument(
        "--max",
        type=int,
        default=4,
        help="Maximum password length for brute-force attack (default: 8)."
    )

    # Arguments specific to mask-based attack
    parser.add_argument(
        "--pattern",
        type=str,
        help="Mask for mask-based attack (e.g., '?l?l?l?d' for three lowercase letters and a digit)."
    )
    parser.add_argument(
        "--custom",
        type=str,
        help="Custom string appended to end of mask (e.g., '2024')."
    )
    parser.add_argument(
        "--phone",
        action="store_true",
        help="Adds phonetic rules to the mask crack, so that all combinations are pronounceable.",
        default=None
    )

    # Arguments specific to rule-based attack
    parser.add_argument(
        "--rules",
        type=str,
        help="Path to rule file for rule-based attack."
    )
    parser.add_argument(
        "--wordlist1",
        type=str,
        help="Path to the first wordlist for rule-based attack."
    )
    parser.add_argument(
        "--wordlist2",
        type=str,
        help="Path to the second wordlist for rule-based attack."
    )
    parser.add_argument(
        "--max-expansions-per-word",
        type=int,
        help="Cap rule expansions per base word (rule mode)."
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        help="Global cap on total rule-generated candidates (rule mode)."
    )

    # Handle Simulated Arguments Only When No CLI Arguments
    if config and len(sys.argv) <= 1:
        simulated_args = []
        for key, value in config.items():
            if key == "operation":
                simulated_args.append(f"--{value}")
            elif key in ["target_file", "password_list"] and value is not None:
                simulated_args.append(value)
            elif key == "rules" and value is not None:
                simulated_args.extend(["--rules", value])
            elif value is not None:
                simulated_args.extend([f"--{key}", str(value)])
        
        print("Simulated Arguments:", simulated_args)  # Debugging Simulated Arguments
        sys.argv.extend(simulated_args)

    # Parse arguments
    args = parser.parse_args()
    return args
