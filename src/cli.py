"""CLI argument parser for ScamShield VN pipeline.

Defines the command-line interface with subcommands for each pipeline phase.
"""

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser with subcommands for collect, process,
        export, validate, and run.
    """
    parser = argparse.ArgumentParser(
        prog="scamshield-vn",
        description="ScamShield VN - Vietnamese Scam & Phishing Dataset Pipeline",
    )

    # Global options
    parser.add_argument(
        "--config",
        type=str,
        default="config/sources.yaml",
        help="Path to the source registry YAML config (default: config/sources.yaml)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./data",
        help="Base output directory for data tiers (default: ./data)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG level) logging output",
    )

    # Subcommands
    subparsers = parser.add_subparsers(
        dest="command",
        help="Pipeline phase to execute",
    )

    # collect subcommand
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect raw data from configured sources",
    )
    collect_parser.add_argument(
        "--source",
        type=str,
        default=None,
        help="Specific source_id to collect from (default: all enabled sources)",
    )

    # process subcommand
    subparsers.add_parser(
        "process",
        help="Process and normalize collected raw data",
    )

    # export subcommand
    export_parser = subparsers.add_parser(
        "export",
        help="Export processed data to target format",
    )
    export_parser.add_argument(
        "--target",
        type=str,
        choices=["kaggle", "all"],
        default="all",
        help="Export target format (default: all)",
    )

    # validate subcommand
    subparsers.add_parser(
        "validate",
        help="Validate dataset integrity and generate quality report",
    )

    # run subcommand (full pipeline)
    subparsers.add_parser(
        "run",
        help="Run the full pipeline: collect -> process -> export -> validate",
    )

    return parser
