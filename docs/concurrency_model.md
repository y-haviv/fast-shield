FastShield Concurrency Model
============================

Pipeline Overview
-----------------
FastShield uses a three-stage pipeline:
1. Reader thread pulls sequential chunks from disk.
2. Worker thread pool encrypts/decrypts chunks in parallel.
3. Writer thread emits chunks in original order.

This design keeps disk I/O and CPU encryption work overlapped while avoiding large memory spikes.

Queues and Backpressure
-----------------------
- Two bounded blocking queues connect the stages.
  - Reader -> Workers (toEncrypt/toDecrypt)
  - Workers -> Writer (toWrite)
- Each queue has a finite capacity (default: 2x number of threads).
- When a queue is full, upstream stages block, providing natural backpressure.

Ordering Guarantees
-------------------
- Each chunk is tagged with an incremental index.
- The writer uses a pending map keyed by index to reassemble order.
- Chunks are written only when all previous indexes are complete.

Thread Safety
-------------
- Input and output files are used by separate threads.
- Worker threads operate on independent chunk buffers.
- The HMAC context is updated in only one thread per mode:
  - Encrypt: Writer thread updates HMAC with ciphertext.
  - Decrypt: Reader thread updates HMAC with ciphertext.

Failure Handling
----------------
- Any thread that encounters an exception closes both queues.
- A shared stop flag informs other threads to exit gracefully.
- The main thread joins all workers and rethrows the first error.

Why This Works
--------------
ChaCha20 is a stream cipher with a position-based keystream. Each chunk is encrypted using its absolute byte offset, so chunks are independent and safe to process in parallel without requiring in-order execution.
