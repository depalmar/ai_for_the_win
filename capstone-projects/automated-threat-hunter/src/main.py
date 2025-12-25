#!/usr/bin/env python3
"""
Automated Threat Hunter - Main Entry Point

Multi-stage threat detection pipeline with ML and LLM analysis.
"""

import argparse

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()
console = Console()


def run_demo():
    """Run demo with sample events."""
    console.print("[yellow]Running in demo mode with sample events...[/yellow]\n")

    # Sample events for demonstration
    demo_events = [
        {
            "timestamp": "2024-01-15T09:15:00Z",
            "host": "WORKSTATION-42",
            "event_type": "process",
            "process": "powershell.exe",
            "command_line": "powershell -enc SGVsbG8gV29ybGQ=",
        },
        {
            "timestamp": "2024-01-15T09:15:05Z",
            "host": "WORKSTATION-42",
            "event_type": "network",
            "dest_ip": "185.143.223.47",
            "dest_port": 443,
        },
    ]

    console.print(f"[green]Loaded {len(demo_events)} demo events[/green]")

    # TODO: Process through pipeline
    # from pipeline.ingestor import EventIngestor
    # from pipeline.ml_filter import MLFilter
    # from pipeline.llm_enricher import LLMEnricher
    # from pipeline.correlator import Correlator
    # from pipeline.verdict import VerdictGenerator

    console.print("\n[yellow]Pipeline stages:[/yellow]")
    console.print("  1. Ingest & Normalize - TODO")
    console.print("  2. ML Filter - TODO")
    console.print("  3. LLM Enrich - TODO")
    console.print("  4. Correlate - TODO")
    console.print("  5. Generate Verdict - TODO")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Automated Threat Hunter")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    parser.add_argument("--config", type=str, help="Path to config file")
    args = parser.parse_args()

    console.print(
        Panel.fit(
            "[bold red]Automated Threat Hunter[/bold red]\n" "ML + LLM Threat Detection Pipeline",
            border_style="red",
        )
    )

    if args.demo:
        run_demo()
    else:
        console.print("\n[yellow]Starting threat detection pipeline...[/yellow]")
        console.print("Use --demo flag to run with sample data")
        console.print("\nComplete the TODOs to enable the full pipeline!")


if __name__ == "__main__":
    main()
