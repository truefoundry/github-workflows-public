#!/usr/bin/env python3
"""
get-vulnerabilities.py

Append CVE IDs of a given severity from a Grype JSON report to the
`ignore` section of a Grype configuration YAML file.

Exit codes
----------
0  Success (report processed, config updated or already up-to-date)
1  CLI usage error
2  Report file not found / unreadable
3  Invalid JSON
4  Invalid YAML
"""

from __future__ import annotations

import argparse
import json
import logging
import pathlib
import sys
from typing import Any, Dict, Set

import yaml

LOGGER = logging.getLogger(__name__)
DEFAULT_GRYPE_CONFIG_FILE = ".grype.yaml"
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "unknown"}


# --------------------------------------------------------------------------- #
# CLI handling
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Append CVEs of the chosen severity from a Grype JSON report "
            "to the ignore list of a Grype configuration."
        )
    )
    parser.add_argument(
        "-o",
        "--output-file",
        metavar="REPORT",
        help="Path to the Grype JSON report (e.g. vulnerability-report.json)",
    )
    parser.add_argument(
        "-s",
        "--severity",
        default="critical",
        choices=sorted(ALLOWED_SEVERITIES),
        help="Severity level to capture (default: %(default)s)",
    )
    parser.add_argument(
        "-c",
        "--config",
        default= DEFAULT_GRYPE_CONFIG_FILE,
        help=f"Path to the Grype configuration file (default: {DEFAULT_GRYPE_CONFIG_FILE})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    return parser.parse_args()


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logging.basicConfig(format="%(asctime)s - %(levelname)s: %(message)s", level=level)


# --------------------------------------------------------------------------- #
# File helpers
# --------------------------------------------------------------------------- #
def load_json(path: pathlib.Path) -> Dict[str, Any]:
    try:
        with path.open() as f:
            return json.load(f)
    except FileNotFoundError:
        LOGGER.error("Report file %s does not exist.", path)
        sys.exit(2)
    except json.JSONDecodeError as exc:
        LOGGER.error("Invalid JSON in report file %s: %s", path, exc)
        sys.exit(3)


def load_yaml(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {}

    try:
        with path.open() as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        LOGGER.error("Invalid YAML in config file %s: %s", path, exc)
        sys.exit(4)

def extract_cves(cves: list[dict[str, Any]], min_severity: str) -> list[dict[str, Any]]:
    """
    cves: iterable of CVE objects/dicts with a 'severity' field (e.g. 'low', 'medium', 'high', 'critical')
    min_severity: one of 'low', 'medium', 'high', 'critical'
    Returns only those CVEs whose severity is >= min_severity.
    """
    # Define the ordering of severities
    severity_order = ['low', 'medium', 'high', 'critical']

    min_severity = min_severity.lower()
    if min_severity not in severity_order:
        raise ValueError(f"min_severity must be one of {severity_order!r}, got {min_severity!r}")

    # Find the cutoff index
    cutoff = severity_order.index(min_severity)

    # Filter CVEs whose severity rank is at or above the cutoff
    filtered = []
    for cve in cves:
        sev = cve.get('severity', '').lower()
        if sev in severity_order and severity_order.index(sev) >= cutoff:
            filtered.append(cve)
    return filtered


def update_grype_config(config_path: pathlib.Path, cves: Set[str]):
    """Add new CVE IDs to the `ignore` list and return the number added."""
    cfg = load_yaml(config_path)

    # Ensure we are working with a list
    grype_cves_ignore_list = cfg.get("ignore", [])
    if not isinstance(grype_cves_ignore_list, list):
        LOGGER.warning("`ignore` key is not a list; overwriting with a new list.")
        grype_cves_ignore_list = []

    # Build a set of CVE IDs already present (handles both str and dict forms)
    existing: Set[str] = set()
    for entry in grype_cves_ignore_list:
        if isinstance(entry, str):
            existing.add(entry)
        elif isinstance(entry, dict):
            # Common dict styles: {"vulnerability": "CVE-XXXX-YYYY"} or {"id": "..."}
            for key in ("vulnerability", "id"):
                vid = entry.get(key)
                if vid:
                    existing.add(vid)

    new_cves = sorted(cves - existing)
    if not new_cves:
        LOGGER.info("No new CVEs to add; configuration already up-to-date.")

    # Append new CVEs. If the existing list uses dict style, keep style consistent
    uses_dict_style = any(isinstance(e, dict) for e in grype_cves_ignore_list)
    for cve in new_cves:
        grype_cves_ignore_list.append({"vulnerability": cve} if uses_dict_style else cve)

    cfg["ignore"] = grype_cves_ignore_list

    with config_path.open("w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)

    LOGGER.info("Added %d CVE(s) to %s", len(new_cves), config_path)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)

    report_path = pathlib.Path(args.output_file)
    config_path = pathlib.Path(args.config)

    report_data = load_json(report_path)
    # Extract vulnerability dicts from Grype report matches
    raw_matches = report_data.get("matches", [])
    vulnerabilities = [match.get("vulnerability", {}) for match in raw_matches]
    # Filter vulnerabilities by severity
    filtered = extract_cves(vulnerabilities, args.severity)
    # Extract CVE ID strings from filtered vulnerabilities
    cves = {vuln.get("id") for vuln in filtered if vuln.get("id")}

    if not cves:
        LOGGER.info("No %s CVEs found in report.", args.severity)
        sys.exit(0)

    update_grype_config(config_path, cves)
    sys.exit(0)


if __name__ == "__main__":
    main()