#!/usr/bin/env python3
"""
Security Analyst Copilot - Main Entry Point

A conversational AI assistant for security analysts.
"""

import os

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

load_dotenv()
console = Console()


def main():
    """Main entry point for the Security Analyst Copilot."""
    console.print(
        Panel.fit(
            "[bold blue]Security Analyst Copilot[/bold blue]\n"
            "Your AI assistant for security investigations",
            border_style="blue",
        )
    )

    # TODO: Initialize the copilot agent
    # from agent.copilot import SecurityCopilot
    # copilot = SecurityCopilot()

    console.print("\n[yellow]Welcome! I'm your Security Analyst Copilot.[/yellow]")
    console.print("I can help you with:")
    console.print("  - Investigating alerts and events")
    console.print("  - Looking up threat intelligence")
    console.print("  - Mapping to MITRE ATT&CK")
    console.print("  - Generating incident documentation")
    console.print("\nType 'quit' to exit.\n")

    while True:
        try:
            user_input = console.input("[bold green]You:[/bold green] ")

            if user_input.lower() in ["quit", "exit", "q"]:
                console.print("\n[yellow]Goodbye! Stay secure.[/yellow]")
                break

            if not user_input.strip():
                continue

            # TODO: Process user input through the copilot
            # response = copilot.chat(user_input)
            response = "I'm still being developed. Complete the TODOs to enable my capabilities!"

            console.print(f"\n[bold blue]Copilot:[/bold blue]")
            console.print(Panel(Markdown(response), border_style="blue"))
            console.print()

        except KeyboardInterrupt:
            console.print("\n\n[yellow]Interrupted. Goodbye![/yellow]")
            break


if __name__ == "__main__":
    main()
