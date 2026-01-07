#!/usr/bin/env python3
"""
Analyze profiling data from concurrent workload to identify bottlenecks.

This script examines:
1. Operation count distribution (reads vs writes vs metadata)
2. Latency patterns and outliers
3. Cache efficiency metrics
4. Potential lock contention signals
"""

import re
import json
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List

@dataclass
class MetricsSnapshot:
    """Captured metrics from VaultStats output."""
    total_reads: int
    total_writes: int
    total_metadata_ops: int
    bytes_read: int
    bytes_written: int
    read_latency_ms: float
    write_latency_ms: float
    metadata_latency_ms: float
    cache_hits: int
    cache_misses: int
    cache_entries: int
    errors: int

    @property
    def total_ops(self) -> int:
        return self.total_reads + self.total_writes + self.total_metadata_ops

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0

    @property
    def read_percentage(self) -> float:
        return (self.total_reads / self.total_ops * 100) if self.total_ops > 0 else 0.0

    @property
    def write_percentage(self) -> float:
        return (self.total_writes / self.total_ops * 100) if self.total_ops > 0 else 0.0

    @property
    def metadata_percentage(self) -> float:
        return (self.total_metadata_ops / self.total_ops * 100) if self.total_ops > 0 else 0.0

def parse_timing_from_log(log_file: Path) -> Optional[str]:
    """Extract benchmark timing from oxbench output."""
    try:
        with open(log_file, 'r') as f:
            content = f.read()

        # Remove ANSI codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean = ansi_escape.sub('', content)

        # Find timing line
        timing_match = re.search(r'Time \(mean ± σ\):\s+([^\n]+)', clean)
        if timing_match:
            return timing_match.group(1)
    except Exception as e:
        print(f"Error parsing {log_file}: {e}", file=sys.stderr)

    return None

def analyze_log_patterns(log_file: Path) -> Dict[str, int]:
    """Analyze debug log for operation type distribution."""
    patterns = {
        'stat_calls': 0,
        'lookup_calls': 0,
        'read_calls': 0,
        'write_calls': 0,
        'mkdir_calls': 0,
        'unlink_calls': 0,
        'cache_lookups': 0,
        'cache_hits': 0,
        'cache_misses': 0,
    }

    try:
        with open(log_file, 'r') as f:
            for line in f:
                if 'getattr' in line or 'stat' in line.lower():
                    patterns['stat_calls'] += 1
                if 'lookup' in line.lower():
                    patterns['lookup_calls'] += 1
                if 'read' in line.lower():
                    patterns['read_calls'] += 1
                if 'write' in line.lower():
                    patterns['write_calls'] += 1
                if 'mkdir' in line.lower():
                    patterns['mkdir_calls'] += 1
                if 'unlink' in line.lower():
                    patterns['unlink_calls'] += 1
                if 'cache hit' in line.lower():
                    patterns['cache_hits'] += 1
                if 'cache miss' in line.lower():
                    patterns['cache_misses'] += 1
    except Exception as e:
        print(f"Error analyzing {log_file}: {e}", file=sys.stderr)

    return patterns

def main():
    """Main analysis routine."""
    profile_dirs = sorted(Path('profiles').glob('concurrent_*'))
    if not profile_dirs:
        print("No profile directories found. Run profiling first.", file=sys.stderr)
        return

    latest_profile = profile_dirs[-1]
    print(f"Analyzing profile: {latest_profile.name}\n")

    # Check available log files
    baseline_log = latest_profile / 'concurrent_baseline.log'
    debug_log = latest_profile / 'concurrent_debug.log'
    verbose_log = latest_profile / 'concurrent_verbose.log'

    print("=" * 60)
    print("TIMING RESULTS")
    print("=" * 60)

    if baseline_log.exists():
        timing = parse_timing_from_log(baseline_log)
        if timing:
            print(f"Concurrent workload (2 iterations):")
            print(f"  {timing}")

    print()
    print("=" * 60)
    print("OPERATION PATTERN ANALYSIS")
    print("=" * 60)

    if debug_log.exists():
        patterns = analyze_log_patterns(debug_log)
        print(f"Operation counts from debug log:")
        for op, count in patterns.items():
            if count > 0:
                print(f"  {op}: {count}")

    print()
    print("=" * 60)
    print("KEY FINDINGS TO INVESTIGATE")
    print("=" * 60)
    print("""
The concurrent workload spawns 4 threads:
  1. Editor (read-modify-write on 3 files, 100ms interval)
  2. File watcher (stat all files every 500ms)
  3. Build process (full read + writes every 5 sec)
  4. Terminal (random reads + dir listings every 50-150ms)

Look for:
  - Which operation type dominates (stat >> read > write)?
  - Are latencies consistent or variable?
  - Is cache hit rate low (indicating thrashing)?
  - Do errors increase under load?

Next steps:
  1. Review detailed logs: cat {latest_profile}/concurrent_debug.log
  2. Look for outliers: grep -i 'latency\\|slow\\|timeout' {latest_profile}/*.log
  3. Check cache stats: grep -i 'cache' {latest_profile}/concurrent_baseline.log
  4. Examine operation distribution in verbose output
""")

if __name__ == "__main__":
    main()
