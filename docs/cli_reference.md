# FastShield CLI Reference (V2)

## Synopsis
```text
fastshield encrypt -i <input> -o <output> -p <password> [options]
fastshield decrypt -i <input> -o <output> -p <password> [options]
```

## Required
- `-i`, `--input <path>`: input file path
- `-o`, `--output <path>`: output file path
- Password source:
  - `-p`, `--password <text>`
  - `--password-stdin`

## Optional
- `--threads <n>`: worker threads (`0` means auto)
- `--chunk-size <size>`: chunk size, supports `K`, `M`, `G`
- `--direct-io`: enable direct I/O attempt for plaintext path
- `--overwrite`: allow replacing output file
- `--verbose`: debug logging
- `-h`, `--help`: help text
- `--version`: version output

## Examples
Encrypt with stdin password:
```bash
fastshield encrypt -i dataset.bin -o dataset.fs --password-stdin --threads 8 --chunk-size 8M
```

Decrypt with direct I/O attempt:
```bash
fastshield decrypt -i dataset.fs -o dataset.bin --password-stdin --direct-io --chunk-size 4096
```

## Direct I/O Constraints
When `--direct-io` is enabled, alignment constraints from the underlying OS/device apply. FastShield validates these constraints and fails with a clear error when requirements are not met.
