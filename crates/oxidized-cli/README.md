# oxcrypt

A command-line interface for interacting with [Cryptomator](https://cryptomator.org/) vaults.

## Installation

```bash
cargo install --path .
```

Or from the workspace root:

```bash
cargo install --path crates/oxidized-cli
```

## Usage

```
oxcrypt --vault <PATH> <COMMAND>
```

### Global Options

| Option | Description |
|--------|-------------|
| `--vault <PATH>` | Path to the Cryptomator vault (required, or set `OXCRYPT_VAULT` env var) |
| `--password <PASS>` | Vault passphrase (or set `OXCRYPT_PASSWORD` env var) |
| `-v, --verbose` | Increase verbosity (`-v` info, `-vv` debug, `-vvv` trace) |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

### Commands

#### `ls` - List directory contents

```bash
oxcrypt --vault ~/my-vault ls /Documents
oxcrypt --vault ~/my-vault ls -l              # Long format with details
oxcrypt --vault ~/my-vault ls -a              # Show all (including hidden)
```

#### `cat` - Read file contents

```bash
oxcrypt --vault ~/my-vault cat /Documents/notes.txt
```

#### `tree` - Show directory tree

```bash
oxcrypt --vault ~/my-vault tree
oxcrypt --vault ~/my-vault tree /Documents
oxcrypt --vault ~/my-vault tree --max-depth 2
```

#### `mkdir` - Create a directory

```bash
oxcrypt --vault ~/my-vault mkdir /Documents/NewFolder
oxcrypt --vault ~/my-vault mkdir -p /Deep/Nested/Path   # Create parents
```

#### `touch` - Create an empty file

```bash
oxcrypt --vault ~/my-vault touch /Documents/newfile.txt
```

#### `write` - Write stdin to a file

```bash
# Write content from stdin
echo "Hello, world!" | oxcrypt --vault ~/my-vault write /greeting.txt

# Pipe a file into the vault
cat local-file.txt | oxcrypt --vault ~/my-vault write /remote-file.txt

# Append to existing file
echo "More content" | oxcrypt --vault ~/my-vault write -a /greeting.txt
```

#### `rm` - Remove files or directories

```bash
oxcrypt --vault ~/my-vault rm /Documents/old-file.txt
oxcrypt --vault ~/my-vault rm -r /Documents/OldFolder   # Recursive
oxcrypt --vault ~/my-vault rm -rf /Documents/OldFolder  # Force + recursive
```

#### `cp` - Copy a file

```bash
oxcrypt --vault ~/my-vault cp /source.txt /destination.txt
```

#### `mv` - Move or rename

```bash
oxcrypt --vault ~/my-vault mv /old-name.txt /new-name.txt
oxcrypt --vault ~/my-vault mv /file.txt /Documents/file.txt
```

#### `info` - Show vault information

```bash
oxcrypt --vault ~/my-vault info
```

Displays vault format version, cipher combination, and configuration details.

## Authentication

The vault passphrase can be provided in three ways (in order of precedence):

1. **`--password` flag** (convenient for testing):
   ```bash
   oxcrypt --vault ~/my-vault --password mypassphrase ls
   ```

2. **`OXCRYPT_PASSWORD` environment variable** (for scripting):
   ```bash
   export OXCRYPT_PASSWORD=mypassphrase
   oxcrypt --vault ~/my-vault ls
   ```

3. **Interactive prompt** (most secure, input hidden):
   ```bash
   oxcrypt --vault ~/my-vault ls
   Vault passphrase: ********
   ```

## Examples

```bash
# Using environment variables (recommended)
export OXCRYPT_VAULT=~/Vaults/personal
export OXCRYPT_PASSWORD=secret123
oxcrypt ls
oxcrypt cat /notes.txt
oxcrypt tree

# Or with explicit options
oxcrypt --vault ~/Vaults/personal --password secret123 ls
oxcrypt --vault ~/Vaults/personal --password secret123 cat /notes.txt > notes.txt

# Create a directory structure
oxcrypt mkdir -p /Projects/2024/Q1

# Copy a file
oxcrypt cp /template.md /Projects/2024/Q1/report.md

# Remove old files
oxcrypt rm -r /Archive/2020

# Show vault tree (limited depth)
oxcrypt tree --max-depth 3
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OXCRYPT_VAULT` | Default vault path (instead of `--vault`) |
| `OXCRYPT_PASSWORD` | Vault passphrase (for non-interactive use) |
| `RUST_LOG` | Log level filter (overrides `-v` flags) |

## Benchmarks

Run benchmarks to measure CLI operation performance:

```bash
# Run all CLI benchmarks
cargo bench -p oxidized-cli

# Quick benchmark run (faster, less precise)
cargo bench -p oxidized-cli -- --quick
```

Benchmarks include:
- `init_vault` - Creating a new vault
- `ls_root` - Listing directory contents
- `cat/{1KB,100KB,1MB}` - Reading files of different sizes
- `write/{1KB,100KB,1MB}` - Writing files of different sizes
- `tree/depth_{1,3,5}` - Directory tree traversal at different depths
- `mkdir`, `mkdir_with_parents` - Directory creation
- `cp_100KB`, `mv`, `rm` - File operations

## Supported Vault Format

- Cryptomator Vault Format 8 (Cryptomator 1.6.0+)
- Cipher: SIV_GCM (AES-SIV for filenames, AES-GCM for content)

## License

MPL-2.0
