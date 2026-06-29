"""Main entry point for the ScamShield VN pipeline.

Handles CLI parsing, logging setup, config loading, and subcommand dispatch.
Can be run as: python -m src.main
"""

import sys
from datetime import datetime
from pathlib import Path

from loguru import logger

from src.cli import build_parser
from src.config.env import load_env
from src.config.registry import load_registry
from src.config.settings import load_settings


def setup_logging(verbose: bool, output_dir: str) -> None:
    """Configure loguru with console and file handlers.

    Removes the default handler and sets up:
    - Console handler at INFO (or DEBUG if verbose)
    - JSON file handler in reports/ directory with timestamped filename

    Args:
        verbose: If True, set console logging to DEBUG level.
        output_dir: Base output directory (reports/ is relative to CWD, not output_dir).
    """
    # Remove default loguru handler
    logger.remove()

    # Console handler
    console_level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=console_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )

    # JSON file handler in reports/ directory
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = reports_dir / f"pipeline_{timestamp}.log"

    logger.add(
        str(log_file),
        level="DEBUG",
        serialize=True,  # JSON format
        rotation="10 MB",
    )

    logger.debug("Logging initialized (console={}, file={})", console_level, log_file)


def main() -> None:
    """Main entry point: parse args, setup logging, load config, dispatch."""
    parser = build_parser()
    args = parser.parse_args()

    # No subcommand provided
    if not args.command:
        parser.print_help()
        sys.exit(2)

    # Setup logging
    setup_logging(verbose=args.verbose, output_dir=args.output_dir)

    try:
        # Load configuration
        logger.info("Loading pipeline configuration...")
        settings = load_settings()
        env = load_env()
        registry = load_registry(args.config)

        # Dispatch subcommands
        if args.command == "collect":
            _run_collect(args, registry, settings, env)
        elif args.command == "process":
            _run_process(args, registry, settings)
        elif args.command == "export":
            _run_export(args, registry, settings)
        elif args.command == "validate":
            _run_validate(args, registry, settings)
        elif args.command == "run":
            _run_full_pipeline(args, registry, settings, env)
        else:
            logger.error("Unknown command: {}", args.command)
            sys.exit(2)

    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user.")
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error("Configuration error: {}", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Pipeline failed: {}", e)
        sys.exit(1)

    logger.info("Pipeline completed successfully.")
    sys.exit(0)


def _run_collect(args, registry, settings, env) -> None:
    """Execute the collect phase."""
    source_filter = getattr(args, "source", None)
    if source_filter:
        logger.info("Running collect phase for source: {}", source_filter)
    else:
        logger.info("Running collect phase for all enabled sources...")
    # Placeholder: actual collection logic in later milestones
    logger.info("Collect phase complete (placeholder).")


def _run_process(args, registry, settings) -> None:
    """Execute the process phase."""
    logger.info("Running process phase...")
    # Placeholder: actual processing logic in later milestones
    logger.info("Process phase complete (placeholder).")


def _run_export(args, registry, settings) -> None:
    """Execute the export phase."""
    target = getattr(args, "target", "all")
    logger.info("Running export phase (target={})...", target)
    # Placeholder: actual export logic in later milestones
    logger.info("Export phase complete (placeholder).")


def _run_validate(args, registry, settings) -> None:
    """Execute the validate phase."""
    logger.info("Running validate phase...")
    # Placeholder: actual validation logic in later milestones
    logger.info("Validate phase complete (placeholder).")


def _run_full_pipeline(args, registry, settings, env) -> None:
    """Execute the full pipeline: collect -> process -> export -> validate."""
    logger.info("Running full pipeline (collect -> process -> export -> validate)...")

    _run_collect(args, registry, settings, env)
    _run_process(args, registry, settings)
    _run_export(args, registry, settings)
    _run_validate(args, registry, settings)

    logger.info("Full pipeline run complete.")


if __name__ == "__main__":
    main()
