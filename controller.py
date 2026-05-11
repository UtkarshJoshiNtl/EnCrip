#!/usr/bin/env python3
"""
Controller script for distributed command execution.

This script allows sending signed commands to multiple worker nodes for execution.
"""

import argparse
import json
import sys
import requests
from typing import List, Optional

from token_system import generate_token


def send_command_to_worker(
    worker_url: str, 
    command: str, 
    secret_key: str, 
    user_id: str = "controller",
    max_lifetime_seconds: int = 300
) -> dict:
    """Send a signed command to a worker node.
    
    Args:
        worker_url: URL of the worker (e.g., "http://localhost:8000")
        command: Shell command to execute
        secret_key: Secret key for token signing
        user_id: User ID for the token
        max_lifetime_seconds: Token lifetime in seconds
    
    Returns:
        dict: Response from the worker
    """
    # Generate a signed token with the command
    token = generate_token(
        user_id=user_id,
        secret_key=secret_key,
        command=command,
        max_lifetime_seconds=max_lifetime_seconds
    )
    
    # Prepare the request payload
    # Note: secret_key is NOT sent to worker - token signature is sufficient
    payload = {
        "token": token
    }
    
    # Send the request to the worker
    execute_url = f"{worker_url.rstrip('/')}/execute"
    
    try:
        response = requests.post(
            execute_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=35  # 30s command timeout + 5s buffer
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"Request failed: {str(e)}",
            "worker_url": worker_url
        }


def main():
    """Main controller function."""
    parser = argparse.ArgumentParser(
        description="Distributed command execution controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send command to single worker
  python controller.py "ls -la" http://localhost:8000
  
  # Send command to multiple workers
  python controller.py "hostname" http://worker1:8000 http://worker2:8000
  
  # Use custom secret key and user ID
  python controller.py "uptime" http://localhost:8000 --secret-key mykey --user-id admin
  
  # Set custom token lifetime
  python controller.py "sleep 5" http://localhost:8000 --lifetime 600
        """
    )
    
    parser.add_argument(
        "command",
        help="Shell command to execute on workers"
    )
    
    parser.add_argument(
        "workers",
        nargs="+",
        help="Worker URLs (e.g., http://localhost:8000)"
    )
    
    parser.add_argument(
        "--secret-key",
        default="my_super_secret_key",
        help="Secret key for token signing (default: my_super_secret_key)"
    )
    
    parser.add_argument(
        "--user-id",
        default="controller",
        help="User ID for token (default: controller)"
    )
    
    parser.add_argument(
        "--lifetime",
        type=int,
        default=300,
        help="Token lifetime in seconds (default: 300)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Command: {args.command}")
        print(f"Workers: {args.workers}")
        print(f"User ID: {args.user_id}")
        print(f"Token lifetime: {args.lifetime}s")
        print()
    
    # Send command to all workers
    results = {}
    for worker_url in args.workers:
        if args.verbose:
            print(f"Sending command to {worker_url}...")
        
        result = send_command_to_worker(
            worker_url=worker_url,
            command=args.command,
            secret_key=args.secret_key,
            user_id=args.user_id,
            max_lifetime_seconds=args.lifetime
        )
        
        results[worker_url] = result
        
        if args.verbose:
            print(f"Response from {worker_url}:")
            print(json.dumps(result, indent=2))
            print()
    
    # Print summary
    print("=== Execution Results ===")
    successful_workers = []
    failed_workers = []
    
    for worker_url, result in results.items():
        if result.get("success", False):
            successful_workers.append(worker_url)
            print(f"✅ {worker_url}: SUCCESS")
            if result.get("stdout"):
                print(f"   stdout: {result['stdout'][:200]}{'...' if len(result['stdout']) > 200 else ''}")
            if result.get("stderr"):
                print(f"   stderr: {result['stderr'][:200]}{'...' if len(result['stderr']) > 200 else ''}")
            print(f"   exit_code: {result.get('exit_code', 'N/A')}")
            print(f"   execution_time: {result.get('execution_time', 'N/A'):.3f}s" if isinstance(result.get('execution_time'), (int, float)) else f"   execution_time: {result.get('execution_time', 'N/A')}")
        else:
            failed_workers.append(worker_url)
            print(f"❌ {worker_url}: FAILED")
            print(f"   error: {result.get('error', 'Unknown error')}")
        print()
    
    # Summary
    print(f"Summary: {len(successful_workers)} successful, {len(failed_workers)} failed")
    
    # Exit with error code if any workers failed
    if failed_workers:
        sys.exit(1)


if __name__ == "__main__":
    main()
