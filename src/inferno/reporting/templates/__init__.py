"""
Inferno Report Templates Package.

This module provides Jinja2 templates for generating security
assessment reports in various formats.

Templates:
- base.html.j2: Base HTML template with styling
- executive.md.j2: Executive summary (Markdown)
- technical.md.j2: Technical findings report (Markdown)
- finding.md.j2: Individual finding template (Markdown)
"""

from pathlib import Path

# Template directory path
TEMPLATES_DIR = Path(__file__).parent

# Available templates
TEMPLATES = {
    "base_html": TEMPLATES_DIR / "base.html.j2",
    "executive_md": TEMPLATES_DIR / "executive.md.j2",
    "technical_md": TEMPLATES_DIR / "technical.md.j2",
    "finding_md": TEMPLATES_DIR / "finding.md.j2",
}


def get_template_path(name: str) -> Path:
    """
    Get the path to a template file.

    Args:
        name: Template name (without extension).

    Returns:
        Path to the template file.

    Raises:
        KeyError: If template not found.
    """
    if name not in TEMPLATES:
        available = ", ".join(TEMPLATES.keys())
        raise KeyError(f"Template '{name}' not found. Available: {available}")
    return TEMPLATES[name]


def list_templates() -> list[str]:
    """
    List available templates.

    Returns:
        List of template names.
    """
    return list(TEMPLATES.keys())


__all__ = [
    "TEMPLATES",
    "TEMPLATES_DIR",
    "get_template_path",
    "list_templates",
]
