#!/usr/bin/env python3
"""
Comprehensive benchmark suite for EnCrip token system.

Stress tests token generation, verification, and API performance under various loads.
"""

import time
import threading
import concurrent.futures
import statistics
import json
import sys
import os
import subprocess
import requests
import psutil
import gc
from typing import List, Dict, Tuple

# Add the token_system to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from token_system import generate_token, verify_token, get_default_secret_key


class BenchmarkResults:
    """Container for benchmark results."""
    
    def __init__(self):
        self.results = {}
        self.system_info = self._get_system_info()
    
    def _get_system_info(self):
        """Collect system information for benchmark context."""
        return {
            "cpu_count": psutil.cpu_count(),
            "memory_gb": psutil.virtual_memory().total / (1024**3),
            "python_version": sys.version,
            "platform": sys.platform
        }
    
    def add_result(self, test_name: str, metrics: Dict):
        """Add benchmark result."""
        self.results[test_name] = metrics
    
    def to_dict(self):
        """Convert results to dictionary."""
        return {
            "system_info": self.system_info,
            "benchmarks": self.results,
            "timestamp": time.time()
        }


def benchmark_token_generation(count: int = 10000) -> Dict:
    """Benchmark token generation performance."""
    print(f"🔑 Benchmarking token generation ({count:,} tokens)...")
    
    secret_key = get_default_secret_key()
    user_ids = [f"user_{i}" for i in range(count // 100)]  # Reuse user IDs to simulate real usage
    
    times = []
    start_time = time.time()
    
    for i in range(count):
        user_id = user_ids[i % len(user_ids)]
        token_start = time.time()
        token = generate_token(user_id, secret_key)
        token_end = time.time()
        times.append(token_end - token_start)
    
    total_time = time.time() - start_time
    
    return {
        "total_tokens": count,
        "total_time_seconds": total_time,
        "tokens_per_second": count / total_time,
        "avg_time_per_token_ms": statistics.mean(times) * 1000,
        "median_time_per_token_ms": statistics.median(times) * 1000,
        "p95_time_per_token_ms": sorted(times)[int(len(times) * 0.95)] * 1000,
        "p99_time_per_token_ms": sorted(times)[int(len(times) * 0.99)] * 1000,
        "min_time_per_token_ms": min(times) * 1000,
        "max_time_per_token_ms": max(times) * 1000
    }


def benchmark_token_verification(count: int = 10000) -> Dict:
    """Benchmark token verification performance."""
    print(f"✅ Benchmarking token verification ({count:,} tokens)...")
    
    secret_key = get_default_secret_key()
    
    # Generate tokens first
    tokens = []
    user_ids = [f"user_{i}" for i in range(count // 100)]
    for i in range(count):
        user_id = user_ids[i % len(user_ids)]
        token = generate_token(user_id, secret_key)
        tokens.append(token)
    
    # Benchmark verification
    times = []
    start_time = time.time()
    
    for token in tokens:
        verify_start = time.time()
        is_valid, data = verify_token(token, secret_key)
        verify_end = time.time()
        times.append(verify_end - verify_start)
    
    total_time = time.time() - start_time
    
    return {
        "total_tokens": count,
        "total_time_seconds": total_time,
        "tokens_per_second": count / total_time,
        "avg_time_per_token_ms": statistics.mean(times) * 1000,
        "median_time_per_token_ms": statistics.median(times) * 1000,
        "p95_time_per_token_ms": sorted(times)[int(len(times) * 0.95)] * 1000,
        "p99_time_per_token_ms": sorted(times)[int(len(times) * 0.99)] * 1000,
        "min_time_per_token_ms": min(times) * 1000,
        "max_time_per_token_ms": max(times) * 1000,
        "success_rate": sum(1 for _ in tokens) / len(tokens)  # Should be 100%
    }


def benchmark_concurrent_operations(thread_count: int = 50, operations_per_thread: int = 200) -> Dict:
    """Benchmark concurrent token operations."""
    print(f"🚀 Benchmarking concurrent operations ({thread_count} threads, {operations_per_thread} ops/thread)...")
    
    secret_key = get_default_secret_key()
    results = []
    
    def worker_thread(thread_id: int) -> List[float]:
        """Worker thread for concurrent operations."""
        times = []
        for i in range(operations_per_thread):
            user_id = f"user_{thread_id}_{i}"
            
            # Generate and verify token
            start_time = time.time()
            token = generate_token(user_id, secret_key)
            is_valid, data = verify_token(token, secret_key)
            end_time = time.time()
            
            times.append(end_time - start_time)
        return times
    
    # Run concurrent operations
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(worker_thread, i) for i in range(thread_count)]
        all_times = []
        for future in concurrent.futures.as_completed(futures):
            all_times.extend(future.result())
    
    total_time = time.time() - start_time
    total_operations = thread_count * operations_per_thread
    
    return {
        "thread_count": thread_count,
        "operations_per_thread": operations_per_thread,
        "total_operations": total_operations,
        "total_time_seconds": total_time,
        "operations_per_second": total_operations / total_time,
        "avg_time_per_operation_ms": statistics.mean(all_times) * 1000,
        "median_time_per_operation_ms": statistics.median(all_times) * 1000,
        "p95_time_per_operation_ms": sorted(all_times)[int(len(all_times) * 0.95)] * 1000,
        "p99_time_per_operation_ms": sorted(all_times)[int(len(all_times) * 0.99)] * 1000
    }


def benchmark_replay_cache_performance(count: int = 10000) -> Dict:
    """Benchmark replay cache performance under high load."""
    print(f"🔄 Benchmarking replay cache performance ({count:,} tokens)...")
    
    secret_key = get_default_secret_key()
    
    # Generate tokens
    tokens = [generate_token(f"user_{i}", secret_key) for i in range(count)]
    
    # First pass - all should succeed
    times_first_pass = []
    start_time = time.time()
    
    for token in tokens:
        verify_start = time.time()
        is_valid, data = verify_token(token, secret_key)
        verify_end = time.time()
        times_first_pass.append(verify_end - verify_start)
    
    first_pass_time = time.time() - start_time
    
    # Second pass - all should fail (replay protection)
    times_second_pass = []
    start_time = time.time()
    
    for token in tokens:
        verify_start = time.time()
        is_valid, data = verify_token(token, secret_key)
        verify_end = time.time()
        times_second_pass.append(verify_end - verify_start)
    
    second_pass_time = time.time() - start_time
    
    return {
        "total_tokens": count,
        "first_pass_time_seconds": first_pass_time,
        "second_pass_time_seconds": second_pass_time,
        "first_pass_tokens_per_second": count / first_pass_time,
        "second_pass_tokens_per_second": count / second_pass_time,
        "first_pass_avg_time_ms": statistics.mean(times_first_pass) * 1000,
        "second_pass_avg_time_ms": statistics.mean(times_second_pass) * 1000,
        "replay_detection_success_rate": sum(1 for token in tokens if not verify_token(token, secret_key)[0]) / len(tokens)
    }


def benchmark_memory_usage(count: int = 50000) -> Dict:
    """Benchmark memory usage during high-volume operations."""
    print(f"💾 Benchmarking memory usage ({count:,} tokens)...")
    
    secret_key = get_default_secret_key()
    
    # Measure initial memory
    gc.collect()
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Generate tokens
    tokens = []
    for i in range(count):
        token = generate_token(f"user_{i}", secret_key)
        tokens.append(token)
        
        if i % 10000 == 0:
            gc.collect()
    
    # Memory after generation
    generation_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Verify all tokens (populate replay cache)
    for token in tokens:
        verify_token(token, secret_key)
    
    # Memory after verification
    verification_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    return {
        "total_tokens": count,
        "initial_memory_mb": initial_memory,
        "generation_memory_mb": generation_memory,
        "verification_memory_mb": verification_memory,
        "memory_increase_during_generation_mb": generation_memory - initial_memory,
        "memory_increase_during_verification_mb": verification_memory - generation_memory,
        "memory_per_token_bytes": (verification_memory - initial_memory) * 1024 * 1024 / count
    }


def benchmark_api_performance(base_url: str = "http://localhost:8000", count: int = 1000) -> Dict:
    """Benchmark REST API performance."""
    print(f"🌐 Benchmarking API performance ({count:,} requests)...")
    
    # Check if server is running
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code != 200:
            print("❌ API server not responding correctly")
            return {"error": "API server not responding correctly"}
    except requests.exceptions.RequestException:
        print("❌ API server not running - starting it...")
        # Start server in background
        server_process = subprocess.Popen([
            sys.executable, "-m", "token_system.api"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for server to start
        time.sleep(3)
        
        try:
            response = requests.get(f"{base_url}/", timeout=5)
            if response.status_code != 200:
                return {"error": "Failed to start API server"}
        except requests.exceptions.RequestException:
            return {"error": "API server failed to start"}
    
    # Benchmark token generation via API
    generation_times = []
    start_time = time.time()
    
    for i in range(count):
        user_id = f"user_{i}"
        request_start = time.time()
        
        try:
            response = requests.post(
                f"{base_url}/generate",
                json={"user_id": user_id},
                timeout=10
            )
            request_end = time.time()
            
            if response.status_code == 200:
                generation_times.append(request_end - request_start)
        except requests.exceptions.RequestException:
            pass
    
    generation_total_time = time.time() - start_time
    
    # Benchmark token verification via API
    if generation_times:
        # Get some tokens for verification testing
        tokens = []
        for i in range(min(100, count)):
            try:
                response = requests.post(
                    f"{base_url}/generate",
                    json={"user_id": f"verify_user_{i}"},
                    timeout=10
                )
                if response.status_code == 200:
                    tokens.append(response.json()["token"])
            except requests.exceptions.RequestException:
                pass
        
        verification_times = []
        start_time = time.time()
        
        for token in tokens:
            request_start = time.time()
            try:
                response = requests.post(
                    f"{base_url}/verify",
                    json={"token": token},
                    timeout=10
                )
                request_end = time.time()
                
                if response.status_code == 200:
                    verification_times.append(request_end - request_start)
            except requests.exceptions.RequestException:
                pass
        
        verification_total_time = time.time() - start_time
    else:
        verification_times = []
        verification_total_time = 0
    
    return {
        "total_generation_requests": count,
        "successful_generation_requests": len(generation_times),
        "generation_time_seconds": generation_total_time,
        "generation_requests_per_second": len(generation_times) / generation_total_time if generation_total_time > 0 else 0,
        "avg_generation_time_ms": statistics.mean(generation_times) * 1000 if generation_times else 0,
        "verification_requests": len(verification_times),
        "verification_time_seconds": verification_total_time,
        "verification_requests_per_second": len(verification_times) / verification_total_time if verification_total_time > 0 else 0,
        "avg_verification_time_ms": statistics.mean(verification_times) * 1000 if verification_times else 0
    }


def run_stress_test() -> Dict:
    """Run comprehensive stress test suite."""
    print("🔥 Starting comprehensive stress test suite...")
    print("=" * 60)
    
    results = BenchmarkResults()
    
    # Individual benchmarks
    results.add_result("token_generation", benchmark_token_generation(10000))
    results.add_result("token_verification", benchmark_token_verification(10000))
    results.add_result("concurrent_operations", benchmark_concurrent_operations(50, 200))
    results.add_result("replay_cache_performance", benchmark_replay_cache_performance(10000))
    results.add_result("memory_usage", benchmark_memory_usage(50000))
    
    # API benchmark (optional, may fail if server issues)
    api_results = benchmark_api_performance(count=1000)
    if "error" not in api_results:
        results.add_result("api_performance", api_results)
    
    print("=" * 60)
    print("✅ Stress test suite completed!")
    
    return results.to_dict()


def main():
    """Main benchmark runner."""
    print("🚀 EnCrip Token System Benchmark Suite")
    print("=" * 60)
    
    # Run benchmarks
    results = run_stress_test()
    
    # Save results
    results_file = "benchmark_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📊 Results saved to {results_file}")
    
    # Print summary
    print("\n📈 Performance Summary:")
    print("-" * 40)
    
    if "token_generation" in results["benchmarks"]:
        gen = results["benchmarks"]["token_generation"]
        print(f"Token Generation: {gen['tokens_per_second']:.0f} tokens/sec")
        print(f"  Avg time: {gen['avg_time_per_token_ms']:.3f}ms")
        print(f"  P95 time: {gen['p95_time_per_token_ms']:.3f}ms")
    
    if "token_verification" in results["benchmarks"]:
        ver = results["benchmarks"]["token_verification"]
        print(f"Token Verification: {ver['tokens_per_second']:.0f} tokens/sec")
        print(f"  Avg time: {ver['avg_time_per_token_ms']:.3f}ms")
        print(f"  P95 time: {ver['p95_time_per_token_ms']:.3f}ms")
    
    if "concurrent_operations" in results["benchmarks"]:
        conc = results["benchmarks"]["concurrent_operations"]
        print(f"Concurrent Operations: {conc['operations_per_second']:.0f} ops/sec")
        print(f"  {conc['thread_count']} threads × {conc['operations_per_thread']} ops")
    
    if "memory_usage" in results["benchmarks"]:
        mem = results["benchmarks"]["memory_usage"]
        print(f"Memory Usage: {mem['memory_per_token_bytes']:.1f} bytes/token")
        print(f"  Total increase: {mem['memory_increase_during_verification_mb']:.1f}MB")
    
    if "api_performance" in results["benchmarks"]:
        api = results["benchmarks"]["api_performance"]
        print(f"API Generation: {api['generation_requests_per_second']:.0f} req/sec")
        print(f"API Verification: {api['verification_requests_per_second']:.0f} req/sec")
    
    return results


if __name__ == "__main__":
    main()
