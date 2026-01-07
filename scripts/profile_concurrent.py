#!/usr/bin/env python3
"""
Detailed profiling of concurrent workload with operation-level metrics.

This script monitors a FUSE mount in real-time and captures:
- Operation rates (ops/sec)
- Latency distributions (read, write, metadata)
- Cache efficiency (hit rate, evictions)
- Throughput (bytes/sec)
"""

import json
import subprocess
import time
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class StatsSnapshot:
    timestamp: float
    total_reads: int
    total_writes: int
    total_metadata_ops: int
    bytes_read: int
    bytes_written: int
    read_latency_avg_ms: float
    write_latency_avg_ms: float
    metadata_latency_avg_ms: float
    cache_hits: int
    cache_misses: int
    cache_entries: int
    errors: int

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0

def get_mount_stats(mount_point: Path) -> Optional[dict]:
    """Get stats for a mount point using oxcrypt stats command."""
    try:
        # Extract socket path from mount point metadata
        # For now, rely on finding it via mount info
        result = subprocess.run(
            ["oxcrypt", "stats"],
            capture_output=True,
            timeout=5,
            text=True
        )

        if result.returncode != 0:
            return None

        # Parse the stats output - it should have JSON in it
        lines = result.stdout.split('\n')
        for line in lines:
            if line.startswith('{'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue

        return None
    except Exception as e:
        print(f"Error getting stats: {e}", file=sys.stderr)
        return None

def extract_snapshot(stats: dict) -> Optional[StatsSnapshot]:
    """Extract relevant metrics from stats output."""
    try:
        return StatsSnapshot(
            timestamp=time.time(),
            total_reads=stats.get('total_reads', 0),
            total_writes=stats.get('total_writes', 0),
            total_metadata_ops=stats.get('total_metadata_ops', 0),
            bytes_read=stats.get('bytes_read', 0),
            bytes_written=stats.get('bytes_written', 0),
            read_latency_avg_ms=stats.get('read_latency_avg_ms', 0.0),
            write_latency_avg_ms=stats.get('write_latency_avg_ms', 0.0),
            metadata_latency_avg_ms=stats.get('metadata_latency_avg_ms', 0.0),
            cache_hits=stats.get('cache', {}).get('hits', 0),
            cache_misses=stats.get('cache', {}).get('misses', 0),
            cache_entries=stats.get('cache', {}).get('entries', 0),
            errors=stats.get('total_errors', 0),
        )
    except Exception as e:
        print(f"Error extracting snapshot: {e}", file=sys.stderr)
        return None

def print_header():
    """Print column headers."""
    print(f"{'Time':>8} {'Read/s':>8} {'Write/s':>8} {'Meta/s':>8} "
          f"{'MB/s':>8} {'RdLat':>8} {'WrLat':>8} {'MetaLat':>8} "
          f"{'CacheHit%':>10} {'Entries':>8} {'Errors':>8}")
    print("-" * 110)

def format_throughput(bytes_per_sec: float) -> str:
    """Format bytes per second as human-readable."""
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:.1f}B"
    elif bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec/1024:.1f}K"
    else:
        return f"{bytes_per_sec/(1024*1024):.1f}M"

def main():
    """Main profiling loop."""
    if len(sys.argv) < 2:
        print("Usage: profile_concurrent.py <duration_secs>", file=sys.stderr)
        sys.exit(1)

    duration = int(sys.argv[1])
    start_time = time.time()
    prev_snapshot: Optional[StatsSnapshot] = None

    print(f"Profiling concurrent workload for {duration} seconds...")
    print(f"Sampling every 1 second\n")

    print_header()

    while time.time() - start_time < duration:
        # Get current stats
        stats = get_mount_stats(Path("/"))
        if stats is None:
            print("No mount found, retrying...", file=sys.stderr)
            time.sleep(1)
            continue

        current = extract_snapshot(stats)
        if current is None:
            time.sleep(1)
            continue

        # Calculate rates
        if prev_snapshot is not None:
            dt = current.timestamp - prev_snapshot.timestamp

            reads_per_sec = (current.total_reads - prev_snapshot.total_reads) / dt
            writes_per_sec = (current.total_writes - prev_snapshot.total_writes) / dt
            meta_per_sec = (current.total_metadata_ops - prev_snapshot.total_metadata_ops) / dt
            bytes_per_sec = (current.bytes_read - prev_snapshot.bytes_read) / dt

            elapsed = int(current.timestamp - start_time)

            print(f"{elapsed:>8} {reads_per_sec:>8.1f} {writes_per_sec:>8.1f} "
                  f"{meta_per_sec:>8.1f} {format_throughput(bytes_per_sec):>8} "
                  f"{current.read_latency_avg_ms:>8.2f} {current.write_latency_avg_ms:>8.2f} "
                  f"{current.metadata_latency_avg_ms:>8.2f} {current.cache_hit_rate:>10.1f} "
                  f"{current.cache_entries:>8} {current.errors:>8}")

        prev_snapshot = current
        time.sleep(1)

    print("\nProfiling complete.")

if __name__ == "__main__":
    main()
