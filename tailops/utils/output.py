"""
Output utilities for tailops CLI.
"""

import click
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()


def success(message: str):
    """Print a success message in green."""
    click.echo(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")


def error(message: str):
    """Print an error message in red."""
    click.echo(f"{Fore.RED}✗ {message}{Style.RESET_ALL}", err=True)


def warning(message: str):
    """Print a warning message in yellow."""
    click.echo(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")


def info(message: str):
    """Print an info message in blue."""
    click.echo(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")


def header(message: str):
    """Print a header message in bold."""
    click.echo(f"{Style.BRIGHT}{message}{Style.RESET_ALL}")


def dim(message: str):
    """Print a dimmed message."""
    click.echo(f"{Style.DIM}{message}{Style.RESET_ALL}")


def format_table_row(data: list, widths: list) -> str:
    """Format a table row with proper spacing."""
    formatted_cells = []
    for i, cell in enumerate(data):
        width = widths[i] if i < len(widths) else 20
        formatted_cells.append(str(cell).ljust(width))
    return " ".join(formatted_cells)


def print_table(headers: list, rows: list, show_headers: bool = True):
    """Print a formatted table."""
    if not rows:
        dim("No data to display")
        return
    
    # Calculate column widths
    widths = []
    all_rows = [headers] + rows if show_headers else rows
    
    for col_idx in range(len(headers)):
        max_width = max(
            len(str(row[col_idx])) if col_idx < len(row) else 0
            for row in all_rows
        )
        widths.append(max_width + 2)  # Add padding
    
    # Print headers
    if show_headers:
        header_row = format_table_row(headers, widths)
        header(header_row)
        click.echo("-" * len(header_row))
    
    # Print data rows
    for row in rows:
        click.echo(format_table_row(row, widths))


def confirm(message: str, default: bool = False) -> bool:
    """Ask for user confirmation."""
    return click.confirm(message, default=default)


def prompt(message: str, default: str = None, hide_input: bool = False) -> str:
    """Prompt user for input."""
    return click.prompt(message, default=default, hide_input=hide_input)
