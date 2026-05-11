## Performance Benchmarks

**Test Environment:**
- CPU: 12 cores
- Memory: 3.4 GB
- Python: 3.13.5
- Platform: linux

### � Throughput Performance

**Cryptographic Operations (HMAC-SHA256):**
- HMAC Generation: **569,069 ops/sec** (P95: 0.002ms)
- HMAC Verification: **578,664 ops/sec** (P95: 0.002ms)

**Token Operations:**
- Token Generation: **11,428 tokens/sec** (avg: 0.087ms, P95: 0.100ms)
- Token Verification: **11,925 tokens/sec** (avg: 0.083ms, P95: 0.105ms)

**Concurrent Load:**
- **2,727 ops/sec** (64 threads × 500 ops)
- P95 Latency: 28.36ms

**Burst Handling:**
- **20,000 tokens** verified in 3.99s
- Burst throughput: **5,015 verifications/sec**
- Success rate: 100.0%

**Sustained Performance (60s):**
- **4,656 ops/sec** sustained throughput
- Total operations: 139,690 (93,174 generated, 46,516 verified)
- Memory stable: ✅ (2.4MB growth)
- Error rate: 0.0000%

**Memory Efficiency:**
- **266.4 bytes/token** with replay cache
- 100K tokens memory overhead: 25.4MB
- Generation: 14,630 tokens/sec
- Verification: 12,822 tokens/sec

### 🛡️ Security Validation

**Replay Attack Protection:**
- **100.00%** detection rate (50,000/50,000 blocked)
- Race condition safety: ✅ (100 concurrent attempts, ≤1 succeeded)

**Token Expiration Enforcement:**
- **0.0%** expired tokens correctly rejected
- **100.0%** valid tokens correctly accepted

### 📈 Distributed Execution Scalability

**Worker Scaling Efficiency:**
- Scaling efficiency: **0.0%** (linear scaling: ⚠️)

### 🌐 REST API Performance

---
*Benchmarked on 2026-05-12*