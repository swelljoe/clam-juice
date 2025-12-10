#!/bin/bash
#
# ClamAV Filtered Database Update Script
#
# This script automates the process of filtering ClamAV signature databases
# and deploying them for use. It can be run manually or automated via cron
# or systemd timer.
#
# Usage:
#   ./update-filtered-db.sh [options]
#
# Options:
#   --dry-run    Show what would be done without making changes
#   --force      Force update even if source hasn't changed
#   --verbose    Enable verbose output
#

set -e

# Configuration
SOURCE_DB="/var/lib/clamav/main.cvd"
OUTPUT_DIR="/var/lib/clamav/filtered"
FILTER_PROFILE="linux-only"  # linux-only, embedded, mail-server, or web-server
CLAMAV_USER="clamav" # clamupdate on EL
RESTART_SERVICE="clamav-daemon" # clamd@scan on EL

# Parse command line options
DRY_RUN=false
FORCE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--force] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --dry-run    Show what would be done without making changes"
            echo "  --force      Force update even if source hasn't changed"
            echo "  --verbose    Enable verbose output"
            echo ""
            echo "Configuration (edit script to change):"
            echo "  Source DB:    $SOURCE_DB"
            echo "  Output Dir:   $OUTPUT_DIR"
            echo "  Filter Profile: $FILTER_PROFILE"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Logging functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [VERBOSE] $*"
    fi
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

# Check prerequisites
check_prerequisites() {
    log_verbose "Checking prerequisites..."

    if [ ! -f "$FILTER_TOOL" ]; then
        log_error "Filter tool not found: $FILTER_TOOL"
        exit 1
    fi

    if [ ! -x "$FILTER_TOOL" ]; then
        log_error "Filter tool is not executable: $FILTER_TOOL"
        log_error "Run: chmod +x $FILTER_TOOL"
        exit 1
    fi

    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    if ! command -v sigtool &> /dev/null; then
        log_error "sigtool is not installed (part of ClamAV)"
        exit 1
    fi

    if [ ! -f "$SOURCE_DB" ]; then
        log_error "Source database not found: $SOURCE_DB"
        exit 1
    fi

    log_verbose "Prerequisites check passed"
}

# Check if update is needed
needs_update() {
    if [ "$FORCE" = true ]; then
        log_verbose "Force update requested"
        return 0
    fi

    if [ ! -d "$OUTPUT_DIR" ]; then
        log_verbose "Output directory doesn't exist, update needed"
        return 0
    fi

    # Check if source is newer than output
    local source_time
    source_time=$(stat -c %Y "$SOURCE_DB" 2>/dev/null || stat -f %m "$SOURCE_DB" 2>/dev/null)
    local output_time
    output_time=$(stat -c %Y "$OUTPUT_DIR" 2>/dev/null || stat -f %m "$OUTPUT_DIR" 2>/dev/null)

    if [ -z "$source_time" ] || [ -z "$output_time" ]; then
        log_verbose "Could not determine file times, proceeding with update"
        return 0
    fi

    if [ "$source_time" -gt "$output_time" ]; then
        log "Source database is newer than filtered database"
        return 0
    fi

    log "Filtered database is up to date"
    return 1
}

# Main update function
do_update() {
    log "Starting ClamAV database filtering..."
    log "Source: $SOURCE_DB"
    log "Output: $OUTPUT_DIR"
    log "Profile: $FILTER_PROFILE"

    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would run:"
        echo "$FILTER_TOOL \\"
        echo "  --input \"$SOURCE_DB\" \\"
        echo "  --output \"$OUTPUT_DIR\" \\"
        echo "  --profile \"$FILTER_PROFILE\""
        if [ "$VERBOSE" = true ]; then
            echo "  --verbose"
        fi
        return 0
    fi

    # Build command
    local cmd=("$FILTER_TOOL" "--input" "$SOURCE_DB" "--output" "$OUTPUT_DIR" "--profile" "$FILTER_PROFILE")
    if [ "$VERBOSE" = true ]; then
        cmd+=("--verbose")
    fi

    # Run filter tool
    if "${cmd[@]}"; then
        log "Filtering completed successfully"
    else
        log_error "Filtering failed with exit code $?"
        return 1
    fi

    # Fix permissions
    if [ -d "$OUTPUT_DIR" ]; then
        log_verbose "Setting permissions on $OUTPUT_DIR"
        if command -v chown &> /dev/null; then
            chown -R "$CLAMAV_USER:$CLAMAV_USER" "$OUTPUT_DIR" 2>/dev/null || true
        fi
        chmod -R 644 "$OUTPUT_DIR"/* 2>/dev/null || true
        chmod 755 "$OUTPUT_DIR" 2>/dev/null || true
    fi

    return 0
}

# Restart ClamAV service
restart_clamav() {
    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would restart $RESTART_SERVICE"
        return 0
    fi

    if ! systemctl is-active --quiet "$RESTART_SERVICE"; then
        log "Service $RESTART_SERVICE is not running, skipping restart"
        return 0
    fi

    log "Restarting $RESTART_SERVICE..."
    if systemctl restart "$RESTART_SERVICE"; then
        log "Service restarted successfully"
    else
        log_error "Failed to restart $RESTART_SERVICE"
        return 1
    fi

    return 0
}

# Verify the filtered database
verify_database() {
    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would verify database at $OUTPUT_DIR"
        return 0
    fi

    log_verbose "Verifying filtered database..."

    if ! command -v clamscan &> /dev/null; then
        log_verbose "clamscan not available, skipping verification"
        return 0
    fi

    # Test loading the database
    if clamscan -d "$OUTPUT_DIR" --version &> /dev/null; then
        local sig_count
        sig_count=$(clamscan -d "$OUTPUT_DIR" --version 2>&1 | grep "Known viruses" | awk '{print $3}')
        log "Database verified: $sig_count signatures loaded"
    else
        log_error "Database verification failed"
        return 1
    fi

    return 0
}

# Main execution
main() {
    log "ClamAV Filtered Database Update Script"

    # Check if we have necessary permissions
    if [ ! -w "$(dirname "$OUTPUT_DIR")" ] && [ ! -w "$OUTPUT_DIR" ]; then
        log_error "No write permission for $OUTPUT_DIR"
        log_error "Try running with sudo"
        exit 1
    fi

    check_prerequisites

    if ! needs_update; then
        log "No update needed"
        exit 0
    fi

    if ! do_update; then
        log_error "Update failed"
        exit 1
    fi

    if ! verify_database; then
        log_error "Verification failed"
        exit 1
    fi

    if ! restart_clamav; then
        log_error "Service restart failed"
        exit 1
    fi

    log "Update completed successfully"
}

# Run main function
main
