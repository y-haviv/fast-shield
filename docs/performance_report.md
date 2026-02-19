FastShield Performance Report
=============================

Status
------
This report is a template intended for real benchmarking runs. Fill in the values after collecting measurements on your target system.

Test Environment
----------------
- CPU:
- RAM:
- Storage:
- OS:
- Compiler:
- Build Type:

Methodology
-----------
1. Encrypt files of increasing sizes (1 GiB, 5 GiB, 10 GiB, 50 GiB).
2. Measure total wall time (start to completion).
3. Compute throughput as MB/s.
4. Run each test 3 times and average.

Results (Template)
------------------
| File Size | Threads | Chunk Size | Encrypt MB/s | Decrypt MB/s |
|----------|---------|------------|--------------|--------------|
| 1 GiB    | 4       | 4 MiB      | TBD          | TBD          |
| 5 GiB    | 4       | 4 MiB      | TBD          | TBD          |
| 10 GiB   | 8       | 8 MiB      | TBD          | TBD          |
| 50 GiB   | 8       | 8 MiB      | TBD          | TBD          |

Observations (Template)
-----------------------
- Throughput scales with more threads until disk I/O saturates.
- Larger chunk sizes reduce overhead but increase memory usage.
- Decryption throughput is typically comparable to encryption.

Notes
-----
Record drive model and filesystem, as they influence I/O performance.
