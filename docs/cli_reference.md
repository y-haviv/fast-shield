FastShield CLI Reference
========================

Synopsis
--------
```
fastshield encrypt -i <input> -o <output> -p <password> [options]
fastshield decrypt -i <input> -o <output> -p <password> [options]
```

Required Arguments
------------------
- `-i`, `--input <path>`: Input file path.
- `-o`, `--output <path>`: Output file path.
- Password input: either `-p`, `--password <text>` or `--password-stdin`.

Optional Arguments
------------------
- `--password-stdin`: Read password from stdin (recommended for security).
- `--threads <n>`: Number of worker threads. `0` uses hardware concurrency.
- `--chunk-size <size>`: Chunk size using `K`, `M`, or `G` suffix (e.g., `4M`).
- `--overwrite`: Allow overwriting the output file.
- `--verbose`: Enable debug logging.
- `-h`, `--help`: Show usage.
- `--version`: Show version.

Examples
--------
Encrypt:
```
fastshield encrypt -i bigfile.bin -o bigfile.fs --password-stdin
```

Decrypt:
```
fastshield decrypt -i bigfile.fs -o bigfile.bin --password-stdin
```

Notes
-----
- For large files, increasing chunk size may improve throughput.
- Passwords provided as CLI arguments can appear in shell history.
