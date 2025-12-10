# clam_juice.py ClamAV Signature Filter Tool

Reduce ClamAV database size for specialized use.

ClamAV with the official signature database is quite large, making it inappropriate for use in smaller or embedded systems. It's also wasteful on, for example, a Linux desktop or server that is not handling files for Windows and MacOS clients. I had a requirement to install antivirus/antimalware software on some resource-constrained systems I maintain, and this was the way I could come up with to do that. If you have similar requirements, it may be useful for you, too.

I'm not an expert on the format of these files, this is all best guesses based on reading the files and the docs. Your mileage may vary, and if it breaks you get to keep both pieces. PRs welcome.

## Overview

ClamAV's signature databases contain millions of signatures for malware across all platforms (Windows, Mac, Linux, Android, etc.). If you're running ClamAV on a Linux-only system, 63.5% of those signatures are for Windows malware, and not useful for your environment.

With filtering:

- **82% smaller databases** (443MB → 79MB for Linux-only systems)
- **5x faster scanning** (2.88s → 0.58s)
- **75% less memory usage** (~600MB → ~150MB RAM)

## Quick Start

```bash
# Filter for Linux-only systems (82% size reduction)
./clam_juice.py \
  --input /var/lib/clamav/main.cvd \
  --output /var/lib/clamav/filtered \
  --profile linux-only

# Test it
clamscan -d /var/lib/clamav/filtered /path/to/file

# Configure ClamAV to use it
echo "DatabaseDirectory /var/lib/clamav/filtered" | sudo tee -a /etc/clamav/clamd.conf
sudo systemctl restart clamav-daemon
```

## What Gets Filtered?

### Original Database (main.cvd)

- **Size:** 443 MB uncompressed
- **Signatures:** 6.6 million
- **Platform breakdown:**
  - 63.5% Windows (Win.*)
  - 35.8% Generic/Unknown
  - 0.7% Everything else (Linux, Mac, PDF, Office, etc.)

### After Filtering (linux-only profile)

- **Size:** 79 MB uncompressed
- **Signatures:** 1.2 million
- **Keeps:** Linux, Unix, generic malware, scripts, web threats, cross-platform threats
- **Removes:** Windows PE, Office macros, Mac malware

### File Format Analysis

| Format | Size  | Count     | Description | Linux-only Action |
|--------|-------|-----------|-------------|-------------------|
| .mdb   | 244M  | 4,058,809 | Windows PE section hashes (100% Windows) | Exclude entirely |
| .hsb   | 161M  | 2,365,531 | SHA256 hashes (mostly generic) | Filter by name |
| .ndb   | 23M   | 101,634   | Extended signatures (90% Windows) | Filter by type + name |
| .ldb   | 12M   | 38,889    | Logical signatures | Filter by name |
| .hdb   | 5.0M  | 82,211    | MD5 hashes (53% Windows, 35% PDF) | Filter by name |

clam_juice.py filters all major signature formats.

- .ndb, .hdb, .mdb, .hsb, and .ldb files
- 4 profiles for common scenarios
- Custom filtering by platform and file type
- Up to 95% size reduction

**Usage:**
```bash
# Use a profile
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered --profile linux-only

# Custom filtering
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered \
  --exclude-platforms Win,Doc,Xls,Osx \
  --exclude-types mdb

# See all options
./clam_juice.py --help
./clam_juice.py --list-profiles
```

## Built-in Profiles

### linux-only

Excludes Windows PE, Office documents, and Mac malware.

**Result:** 82% reduction (443MB → 79MB, 6.6M → 1.2M signatures)

```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered --profile linux-only
```

**Keeps:**
- Generic malware
- Linux/Unix malware (ELF binaries)
- Script-based threats (PHP, Python, Bash)
- Web threats (HTML, JavaScript)
- Cross-platform threats (PDF, images)
- Archive exploits
- EICAR test signatures (always kept for testing)

**Removes:**
- Windows PE executables (4M+ signatures)
- Office macro viruses
- Mac/iOS malware

### embedded

Aggressive filtering for severely resource-constrained devices.

**Result:** 95% reduction (443MB → ~20MB)

```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered --profile embedded
```

### mail-server

Optimized for mail servers scanning attachments.

**Result:** 40% reduction

```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered --profile mail-server
```

### web-server

Optimized for web servers scanning uploads.

**Result:** 60% reduction

```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered --profile web-server
```

## Custom Filtering

### By Platform Prefix

Signatures are named with platform prefixes like `Win.Trojan.Agent`, `Doc.Macro.Virus`, etc.

**Common prefixes:**
- `Win.*` - Windows executables (63.5% of all signatures!)
- `Doc.*` - Office documents
- `Xls.*` - Excel spreadsheets
- `Pdf.*` - PDF documents
- `Html.*` - HTML files
- `Unix.*` / `Linux.*` - Linux malware
- `Osx.*` - macOS executables
- `Andr.*` - Android apps
- `Java.*` - Java files

**Example - Exclude Windows and Office:**
```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered \
  --exclude-platforms Win,Doc,Xls,Ppt,Rtf
```

**Example - Keep only specific platforms:**
```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered \
  --include-platforms Unix,Linux,Pdf,Html
```

### By File Type

Exclude entire signature file types.

**Example - Exclude MDB (100% Windows) and HSB (large, generic):**
```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered \
  --exclude-types mdb,hsb
```

### By NDB Type Field

NDB signatures have a type field indicating the file format:

- 0 = Any file (generic)
- 1 = Portable Executable (Windows)
- 2 = OLE2 (Office documents)
- 3 = HTML
- 4 = Mail file
- 5 = Graphics
- 6 = ELF (Linux executables)
- 7 = ASCII text
- 9 = Mach-O (macOS)
- 10 = PDF files
- 11 = Flash files
- 12 = Java files

**Example - Keep only Linux-relevant types:**
```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered \
  --ndb-types 0,5,6,7
```

### Combined Filtering

Combine multiple filters for precise control:

```bash
./clam_juice.py -i /var/lib/clamav/main.cvd -o ./filtered \
  --exclude-platforms Win,Osx,Doc,Xls \
  --exclude-types mdb \
  --ndb-types 0,3,5,6,7
```

## Performance Results

Tested on typical server hardware scanning a 1MB test file:

| Configuration | Size | Signatures | Scan Time | Memory |
|---------------|------|------------|-----------|--------|
| Original | 443 MB | 6.6M | 2.88s | ~600 MB |
| linux-only | 79 MB | 1.2M | 0.58s | ~150 MB |
| embedded | ~20 MB | ~300K | 0.15s | ~50 MB |

### Requirements

- Python 3.6 or later
- ClamAV with `sigtool` (comes with ClamAV)
- root/sudo access to configure ClamAV

### Setup

```bash
# Make scripts executable
chmod +x clam_juice.py
chmod +x update-filtered-db.sh

# Verify sigtool is available
which sigtool
```

**Note:** EICAR test signatures are always kept regardless of filtering rules, ensuring you can always test after filtering.

## Deployment

### Step 1: Filter the Database

```bash
./clam_juice.py \
  --input /var/lib/clamav/main.cvd \
  --output /var/lib/clamav/filtered \
  --profile linux-only
```

### Step 2: Test It

```bash
# Verify it loads
clamscan -d /var/lib/clamav/filtered --version

# Should show: "Known viruses: 1151326"

# Test scanning
clamscan -d /var/lib/clamav/filtered /etc/passwd

# Test EICAR detection
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | clamscan -d /var/lib/clamav/filtered -
# Should detect: "Win.Test.EICAR_HDB-1 FOUND"
```

### Step 3: Configure ClamAV

Edit `/etc/clamav/clamd.conf` and add:

```conf
DatabaseDirectory /var/lib/clamav/filtered
```

**Note:** You can have multiple DatabaseDirectory lines. You may wish to use this feature for other [unofficial signature databases](https://github.com/extremeshok/clamav-unofficial-sigs).

### Step 4: Restart and Verify

```bash
# Ubuntu/Debian
sudo systemctl restart clamav-daemon
sudo systemctl status clamav-daemon

# Check logs
sudo journalctl -u clamav-daemon -n 50
```

```bash
# EL
sudo systemctl restart clamd@scan
sudo systemctl status clamd@scan

sudo journalctl -u clamd@scan -n 50
```

## Automation

### Automatic Updates After freshclam

When ClamAV updates its databases, you'll want to re-filter them.

**Option 1: freshclam hook (Recommended)**

Add to `/etc/clamav/freshclam.conf`:

```conf
OnUpdateExecute /usr/local/bin/update-filtered-db.sh
```

Create `/usr/local/bin/update-filtered-db.sh`:

```bash
#!/bin/bash
/path/to/clam_juice.py \
  --input /var/lib/clamav/main.cvd \
  --output /var/lib/clamav/filtered \
  --profile linux-only

# Fix permissions
chown -R clamav:clamav /var/lib/clamav/filtered

# Restart daemon
systemctl restart clamav-daemon
```

```bash
chmod +x /usr/local/bin/update-filtered-db.sh
```

**Option 2: Cron job**

```bash
sudo crontab -e
```

Add:
```cron
# Run daily at 2 AM (after freshclam typically runs)
0 2 * * * /usr/local/bin/update-filtered-db.sh
```

## Troubleshooting

### Database won't load

Check permissions:
```bash
# Ubuntu/Debian
sudo chown -R clamav:clamav /var/lib/clamav/filtered
sudo chmod 644 /var/lib/clamav/filtered/*
sudo chmod 755 /var/lib/clamav/filtered

# EL
sudo chown -R clamupdate:clamupdate /var/lib/clamav/filtered
sudo chmod 644 /var/lib/clamav/filtered/*
sudo chmod 755 /var/lib/clamav/filtered
```


Check ClamAV logs:
```bash
sudo journalctl -u clamav-daemon -f
```

## FAQ

**Q: Can I filter daily.cvd too?**  
A: Yes. Use the same tool:
```bash
./clam_juice.py -i /var/lib/clamav/daily.cvd -o /var/lib/clamav/daily-filtered --profile linux-only
```

**Q: What about bytecode.cvd?**  
A: The bytecode database is already small (~1-2MB). Usually not worth filtering.

**Q: How often should I re-filter?**  
A: After each database update. Use the automation methods above.

**Q: Can I undo this?**  
A: Yes, just change the DatabaseDirectory back to `/var/lib/clamav` and restart ClamAV.
