#!/usr/bin/env python3
"""
ClamAV Signature Database Filter Tool

This tool filters all major ClamAV signature file formats by platform prefix,
allowing significant database size reduction for specialized environments.

Supported formats:
- .ndb - Extended signatures (filters by type field and name)
- .hdb - Hash database (filters by name prefix)
- .mdb - PE section hash (100% Windows)
- .hsb - SHA256 hash database (filters by name prefix where available)
- .ldb - Logical signatures (filters by name prefix)

Usage:
    ./clam_juice.py --input main.cvd --output ./filtered --profile linux-only
    ./clam_juice.py --input main.cvd --output ./filtered \
        --exclude-platforms Win,Doc,Osx
    ./clam_juice.py --input main.cvd --output ./filtered \
        --include-platforms Unix,Linux --exclude-types mdb,hsb
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections import defaultdict
from pathlib import Path


class ComprehensiveFilter:
    """Filter all ClamAV signature file formats."""

    # Predefined filtering profiles
    PROFILES = {
        "linux-only": {
            "description": "Linux-only system, no Windows/Mac clients",
            "exclude_platforms": ["Win", "Osx", "Doc", "Xls", "Ppt", "Rtf"],
            "exclude_types": ["mdb"],  # MDB is 100% Windows
            "ndb_types": [
                "0",
                "5",
                "6",
                "7",
                "10",
                "12",
            ],  # Any, Graphics, ELF, ASCII, PDF, Java
        },
        "embedded": {
            "description": "Embedded/IoT device with minimal resources",
            "exclude_platforms": [
                "Win",
                "Osx",
                "Doc",
                "Xls",
                "Ppt",
                "Html",
                "Swf",
                "Java",
            ],
            "exclude_types": ["mdb", "hsb", "ldb"],  # Exclude large/complex formats
            "ndb_types": ["0", "6"],  # Any, ELF only
        },
        "mail-server": {
            "description": "Mail server scanning attachments",
            "exclude_platforms": ["Osx", "Dos", "Andr"],
            "exclude_types": [],
            "ndb_types": [
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "10",
                "12",
            ],  # Keep mail-relevant types (excludes Mach-O, Flash)
        },
        "web-server": {
            "description": "Web server scanning uploads",
            "exclude_platforms": ["Win", "Osx", "Dos"],
            "exclude_types": ["mdb"],
            "ndb_types": [
                "0",
                "3",
                "5",
                "7",
                "10",
                "12",
            ],  # Any, HTML, Graphics, ASCII, PDF, Java
        },
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.stats = defaultdict(lambda: {"original": 0, "filtered": 0})

    def log(self, message):
        """Log an informational message if verbose mode is enabled."""
        if self.verbose:
            print(f"[INFO] {message}", file=sys.stderr)

    def error(self, message):
        """Log an error message to stderr."""
        print(f"[ERROR] {message}", file=sys.stderr)

    def run_command(self, cmd, cwd=None):
        """Run a shell command and return its stdout."""
        self.log(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.error(f"Command failed: {' '.join(cmd)}")
            self.error(f"stderr: {e.stderr}")
            raise

    def unpack_cvd(self, cvd_path, extract_dir):
        """Unpack a CVD/CLD file."""
        self.log(f"Unpacking {cvd_path}")
        self.run_command(["sigtool", "--unpack", cvd_path], cwd=extract_dir)

    def should_keep_signature(self, name, exclude_platforms, include_platforms):
        """Determine if a signature should be kept based on its name."""
        # Always keep EICAR test signatures (useful for testing ClamAV functionality)
        if name and ("eicar" in name.lower() or "test.eicar" in name.lower()):
            return True

        if not name or "." not in name:
            # No platform info, keep by default unless we have an include list
            return len(include_platforms) == 0

        prefix = name.split(".")[0]

        if include_platforms:
            return prefix in include_platforms

        if exclude_platforms:
            return prefix not in exclude_platforms

        return True

    def filter_ndb(self, file_path, exclude_platforms, include_platforms, ndb_types):
        """Filter .ndb extended signature file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(":", 3)

                if len(parts) >= 4:
                    name = parts[0]
                    sig_type = parts[1]

                    # Check both platform and type
                    keep_platform = self.should_keep_signature(
                        name, exclude_platforms, include_platforms
                    )
                    keep_type = ndb_types is None or sig_type in ndb_types

                    if keep_platform and keep_type:
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    # Malformed, keep it
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["ndb"]["original"] += original_count
        self.stats["ndb"]["filtered"] += filtered_count
        self.log(f"NDB: kept {filtered_count}/{original_count}")

    def filter_hdb(self, file_path, exclude_platforms, include_platforms):
        """Filter .hdb hash database file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(":")

                if len(parts) >= 3:
                    name = parts[2]  # Format: hash:size:name
                    if self.should_keep_signature(
                        name, exclude_platforms, include_platforms
                    ):
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["hdb"]["original"] += original_count
        self.stats["hdb"]["filtered"] += filtered_count
        self.log(f"HDB: kept {filtered_count}/{original_count}")

    def filter_hsb(self, file_path, exclude_platforms, include_platforms):
        """Filter .hsb SHA256 hash database file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(":")

                if len(parts) >= 3:
                    name = parts[2]  # Format: hash:size:name (or name:extra)
                    # HSB files often don't have platform prefix (99.9% unknown)
                    # If no platform info, keep by default unless strict include list
                    if self.should_keep_signature(
                        name, exclude_platforms, include_platforms
                    ):
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["hsb"]["original"] += original_count
        self.stats["hsb"]["filtered"] += filtered_count
        self.log(f"HSB: kept {filtered_count}/{original_count}")

    def filter_mdb(self, file_path, exclude_platforms, include_platforms):
        """Filter .mdb PE section hash file (100% Windows)."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")

        # Quick check: if excluding Windows, MDB is 100% Windows so skip entire file
        if "Win" in exclude_platforms:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                original_count = sum(
                    1 for line in f if line.strip() and not line.startswith("#")
                )
            # Write empty file (just comments)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("# MDB signatures filtered (100% Windows PE)\n")
            self.stats["mdb"]["original"] += original_count
            self.stats["mdb"]["filtered"] += 0
            self.log(
                f"MDB: excluded entire file ({original_count} Windows PE signatures)"
            )
            return

        # Otherwise filter normally (same format as HDB)
        self.filter_hdb(file_path, exclude_platforms, include_platforms)

    def filter_ldb(self, file_path, exclude_platforms, include_platforms):
        """Filter .ldb logical signature file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                # LDB format: Name;Engine:XX-YY,Target:Z;LogicalExpression;Subsigs...
                parts = line.split(";", 1)

                if len(parts) >= 1:
                    name = parts[0]
                    if self.should_keep_signature(
                        name, exclude_platforms, include_platforms
                    ):
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["ldb"]["original"] += original_count
        self.stats["ldb"]["filtered"] += filtered_count
        self.log(f"LDB: kept {filtered_count}/{original_count}")

    def exclude_file_type(self, file_path):
        """Exclude an entire file type by making it empty."""
        if not os.path.exists(file_path):
            return

        basename = os.path.basename(file_path)
        ext = basename.split(".")[-1]

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            original_count = sum(
                1 for line in f if line.strip() and not line.startswith("#")
            )

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"# {ext.upper()} signatures excluded entirely\n")

        self.stats[ext]["original"] += original_count
        self.stats[ext]["filtered"] += 0
        self.log(f"Excluded entire file: {basename} ({original_count} signatures)")

    def filter_database(
        self,
        input_path,
        output_dir,
        exclude_platforms=None,
        include_platforms=None,
        ndb_types=None,
        exclude_file_types=None,
    ):
        """Main filtering workflow."""

        exclude_platforms = set(exclude_platforms or [])
        include_platforms = set(include_platforms or [])
        exclude_file_types = set(exclude_file_types or [])

        os.makedirs(output_dir, exist_ok=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            self.log(f"Using temporary directory: {temp_dir}")
            self.unpack_cvd(input_path, temp_dir)

            # Filter each file type
            for ndb_file in Path(temp_dir).glob("*.ndb"):
                self.filter_ndb(
                    str(ndb_file), exclude_platforms, include_platforms, ndb_types
                )

            for hdb_file in Path(temp_dir).glob("*.hdb"):
                self.filter_hdb(str(hdb_file), exclude_platforms, include_platforms)

            for hsb_file in Path(temp_dir).glob("*.hsb"):
                if "hsb" in exclude_file_types:
                    self.exclude_file_type(str(hsb_file))
                else:
                    self.filter_hsb(str(hsb_file), exclude_platforms, include_platforms)

            for mdb_file in Path(temp_dir).glob("*.mdb"):
                if "mdb" in exclude_file_types:
                    self.exclude_file_type(str(mdb_file))
                else:
                    self.filter_mdb(str(mdb_file), exclude_platforms, include_platforms)

            for ldb_file in Path(temp_dir).glob("*.ldb"):
                if "ldb" in exclude_file_types:
                    self.exclude_file_type(str(ldb_file))
                else:
                    self.filter_ldb(str(ldb_file), exclude_platforms, include_platforms)

            for ext in exclude_file_types:
                if ext not in ["ndb", "hdb", "hsb", "mdb", "ldb"]:
                    for file in Path(temp_dir).glob(f"*.{ext}"):
                        self.exclude_file_type(str(file))

            # Copy all files to output
            for item in os.listdir(temp_dir):
                src = os.path.join(temp_dir, item)
                dst = os.path.join(output_dir, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

        # Print statistics
        self.print_statistics()
        print(f"\nFiltered database deployed to: {output_dir}")
        print("\nTo use with ClamAV, add to /etc/clamav/clamd.conf:")
        print(f"  DatabaseDirectory {output_dir}")

    def print_statistics(self):
        """Print filtering statistics."""
        print("\n" + "=" * 70)
        print("FILTERING STATISTICS")
        print("=" * 70)

        total_original = 0
        total_filtered = 0

        for file_type in sorted(self.stats.keys()):
            original = self.stats[file_type]["original"]
            filtered = self.stats[file_type]["filtered"]
            total_original += original
            total_filtered += filtered

            if original > 0:
                pct = 100 * filtered / original
                reduction = 100 * (1 - filtered / original)
                print(f"\n.{file_type.upper()} files:")
                print(f"  Original:  {original:10,} signatures")
                print(f"  Filtered:  {filtered:10,} signatures ({pct:5.1f}%)")
                removed = original - filtered
                print(
                    f"  Removed:   {removed:10,} signatures ({reduction:5.1f}% reduction)"
                )

        if total_original > 0:
            total_pct = 100 * total_filtered / total_original
            total_reduction = 100 * (1 - total_filtered / total_original)
            print("\n" + "=" * 70)
            print("TOTAL:")
            print(f"  Original:  {total_original:10,} signatures")
            print(f"  Filtered:  {total_filtered:10,} signatures ({total_pct:5.1f}%)")
            total_removed = total_original - total_filtered
            print(
                f"  Removed:   {total_removed:10,} signatures "
                f"({total_reduction:5.1f}% reduction)"
            )
            print("=" * 70)


def main():
    """Parse arguments and run the ClamAV signature database filter."""
    parser = argparse.ArgumentParser(
        description="ClamAV signature database filter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Filtering Profiles:
  linux-only     - Linux-only system (excludes Windows, Mac, Office)

  embedded       - Embedded/IoT device with minimal resources
                   Removes ~95%% of signatures (aggressive filtering)

  mail-server    - Mail server scanning attachments
                   Keeps most formats, excludes mobile/Mac

  web-server     - Web server scanning uploads
                   Excludes Windows PE, keeps web-relevant formats

Examples:
  # Use a predefined profile
  %(prog)s --input /var/lib/clamav/main.cvd --output ./filtered --profile linux-only

  # Custom filtering: exclude Windows and Office
  %(prog)s --input main.cvd --output ./filtered --exclude-platforms Win,Doc,Xls

  # Keep only specific platforms
  %(prog)s --input main.cvd --output ./filtered --include-platforms Unix,Linux,Pdf

  # Exclude entire file types (e.g., MDB is 100%% Windows)
  %(prog)s --input main.cvd --output ./filtered --exclude-types mdb,hsb

  # Combine multiple filters
  %(prog)s --input main.cvd --output ./filtered \\
           --exclude-platforms Win,Osx,Doc \\
           --exclude-types mdb \\
           --ndb-types 0,5,6,7

Platform Prefixes (case-sensitive):
  Win    - Windows executables (63.5%% of all signatures)
  Doc    - Office documents (.doc, etc.)
  Xls    - Excel spreadsheets
  Pdf    - PDF documents
  Html   - HTML files
  Unix   - Unix/Linux files
  Osx    - macOS executables
  Andr   - Android apps
  Java   - Java files
  Swf    - Flash files

File Types:
  ndb    - Extended signatures (23M, mixed platforms)
  hdb    - Hash database (5M, 53%% Windows)
  mdb    - PE section hash (244M, 100%% Windows)
  hsb    - SHA256 hash (161M, mostly generic)
  ldb    - Logical signatures (12M, mixed)
""",
    )

    parser.add_argument("--input", "-i", help="Input CVD/CLD file path")
    parser.add_argument("--output", "-o", help="Output directory path")

    parser.add_argument(
        "--profile",
        "-p",
        choices=ComprehensiveFilter.PROFILES.keys(),
        help="Use a predefined filtering profile",
    )

    parser.add_argument(
        "--exclude-platforms",
        "-e",
        help="Comma-separated platforms to EXCLUDE (e.g., Win,Doc,Osx)",
    )
    parser.add_argument(
        "--include-platforms",
        help="Comma-separated platforms to INCLUDE (excludes all others)",
    )

    parser.add_argument(
        "--ndb-types", "-t", help="NDB signature types to keep (e.g., 0,5,6,7)"
    )

    parser.add_argument(
        "--exclude-types", help="File types to exclude entirely (e.g., mdb,hsb)"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--list-profiles", action="store_true", help="List available profiles and exit"
    )

    args = parser.parse_args()

    if args.list_profiles:
        print("Available Filtering Profiles:\n")
        for name, profile in ComprehensiveFilter.PROFILES.items():
            print(f"{name}:")
            print(f"  Description: {profile['description']}")
            print(f"  Excludes: {', '.join(profile['exclude_platforms'])}")
            if profile["exclude_types"]:
                print(f"  Excluded file types: {', '.join(profile['exclude_types'])}")
            if profile["ndb_types"]:
                print(f"  NDB types: {', '.join(profile['ndb_types'])}")
            print()
        return

    # Validate required arguments (after --list-profiles check)
    if not args.input or not args.output:
        parser.error("the following arguments are required: --input/-i, --output/-o")

    # Parse arguments
    exclude_platforms = None
    include_platforms = None
    ndb_types = None
    exclude_types = None

    if args.profile:
        profile = ComprehensiveFilter.PROFILES[args.profile]
        exclude_platforms = profile.get("exclude_platforms", [])
        exclude_types = profile.get("exclude_types", [])
        ndb_types = profile.get("ndb_types")
        print(f"Using profile: {args.profile}")
        print(f"Description: {profile['description']}\n")
    else:
        if (
            not args.exclude_platforms
            and not args.include_platforms
            and not args.exclude_types
        ):
            print(
                "Error: Must specify --profile, --exclude-platforms, "
                "--include-platforms, or --exclude-types"
            )
            sys.exit(1)

    # Override with command-line arguments
    if args.exclude_platforms:
        exclude_platforms = [p.strip() for p in args.exclude_platforms.split(",")]

    if args.include_platforms:
        include_platforms = [p.strip() for p in args.include_platforms.split(",")]

    if args.ndb_types:
        ndb_types = set(t.strip() for t in args.ndb_types.split(","))

    if args.exclude_types:
        exclude_types = [t.strip() for t in args.exclude_types.split(",")]

    if exclude_platforms and include_platforms:
        print("Error: Cannot specify both --exclude-platforms and --include-platforms")
        sys.exit(1)

    # Run filter
    filter_tool = ComprehensiveFilter(verbose=args.verbose)

    try:
        filter_tool.filter_database(
            input_path=args.input,
            output_dir=args.output,
            exclude_platforms=exclude_platforms,
            include_platforms=include_platforms,
            ndb_types=ndb_types,
            exclude_file_types=exclude_types,
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
