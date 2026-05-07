# Performance Notes (V2)

## Why V2 Is Faster and More Predictable
- Buffer pooling removes repeated allocation/free overhead in hot paths.
- Chunked AEAD keeps work parallel-friendly and cache-local.
- Cross-platform file abstraction allows backend-specific optimization.
- Optional direct I/O can reduce page-cache churn on bulk operations.

## Benchmark Template
Record on your target host:
- CPU model
- RAM size
- Storage type (NVMe/SATA/network)
- OS + kernel
- Compiler + flags

Run matrix:
- file sizes: 1 GiB, 10 GiB, 100 GiB
- chunk sizes: 1 MiB, 4 MiB, 16 MiB
- threads: 1, half cores, full cores
- direct I/O: off/on

Report:
| File Size | Threads | Chunk | Direct I/O | Encrypt MB/s | Decrypt MB/s |
|---|---:|---:|---|---:|---:|
| 1 GiB | 8 | 4 MiB | off | TBD | TBD |
| 10 GiB | 8 | 8 MiB | off | TBD | TBD |
| 10 GiB | 8 | 8 MiB | on | TBD | TBD |

## Interpretation Guidance
- If throughput plateaus as threads increase, storage is likely saturated.
- If direct I/O improves consistency but not peak speed, cache eviction pressure was the prior bottleneck.
- If tiny chunks degrade speed, scheduling and queue overhead dominate.
