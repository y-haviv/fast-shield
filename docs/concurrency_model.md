# Concurrency Model (V2)

## Pipeline
FastShield uses a three-stage bounded pipeline:
1. Reader thread
2. Worker pool
3. Writer thread

## Buffer Lifecycle
- Reader acquires an aligned chunk buffer from `BufferPool`.
- Buffer moves through queues without copying.
- Worker encrypts/decrypts in place and attaches AEAD tag.
- Writer persists output and releases buffer back to pool via RAII.

This removes per-chunk heap allocation (`std::vector` growth/teardown) from steady-state processing.

## Queues and Backpressure
Two bounded queues enforce flow control:
- Reader -> Workers
- Workers -> Writer

If downstream is slower, upstream blocks, preventing unbounded memory growth.

## Ordering
Each chunk carries an index. Writer stores out-of-order arrivals in a pending map and emits strictly increasing index order.

## Failure Semantics
Any exception in any stage:
- stores first error
- sets stop flag
- closes queues
- shuts down buffer pool
- joins threads
- rethrows in caller

Partial output artifacts are deleted by `OutputGuard` unless successful completion is reached.
