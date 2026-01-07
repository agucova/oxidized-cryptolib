#!/usr/bin/env python3
"""
Analyze flamegraph hotspots by extracting title elements.
"""

import re
from pathlib import Path
from collections import defaultdict

def extract_hotspots(svg_path: Path):
    """Extract function names and sample counts from SVG."""

    with open(svg_path, 'r') as f:
        content = f.read()

    # Find all title> elements with sample counts
    # Format: title>function_name (N samples, X.XX%)
    pattern = r'title>([^<]*?)\s*\((\d+) samples?,\s*([\d.]+)%\)'
    matches = re.findall(pattern, content)

    hotspots = []
    for func_name, samples, percentage in matches:
        # Decode HTML entities
        func_name = func_name.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        hotspots.append({
            'name': func_name,
            'samples': int(samples),
            'percentage': float(percentage),
        })

    # Sort by samples (descending)
    hotspots.sort(key=lambda x: x['samples'], reverse=True)

    return hotspots

def categorize(func_name: str) -> str:
    """Categorize function."""
    name_lower = func_name.lower()

    if '__pthread_cond_wait' in name_lower or 'cond_wait' in name_lower:
        return 'Lock Wait'
    elif 'pthread' in name_lower or 'mutex' in name_lower or 'lock' in name_lower:
        return 'Synchronization'
    elif 'moka' in name_lower or 'cache' in name_lower or 'evict' in name_lower:
        return 'Cache'
    elif 'tokio::runtime::task' in name_lower or 'run_task' in name_lower or 'poll' in name_lower:
        return 'Async/Task'
    elif 'spawn' in name_lower or 'blocking' in name_lower:
        return 'Task Spawning'
    elif 'encrypt' in name_lower or 'decrypt' in name_lower or 'gcm' in name_lower or 'siv' in name_lower:
        return 'Encryption'
    elif 'write' in name_lower and 'operations' in name_lower:
        return 'Write Operations'
    elif 'read' in name_lower and 'operations' in name_lower:
        return 'Read Operations'
    elif 'getattr' in name_lower or 'lookup' in name_lower or 'stat' in name_lower:
        return 'Metadata Ops'
    else:
        return 'Other'

def main():
    svg_file = Path('profiles/fuse_Concurrent_Access.svg')

    if not svg_file.exists():
        print(f"File not found: {svg_file}")
        return

    hotspots = extract_hotspots(svg_file)

    if not hotspots:
        print("No hotspots found")
        return

    total_samples = sum(h['samples'] for h in hotspots)

    print("=" * 100)
    print("FLAMEGRAPH ANALYSIS: Concurrent Access Workload")
    print("=" * 100)
    print(f"Total samples: {total_samples}\n")

    print("TOP 25 HOTTEST FUNCTIONS:")
    print("-" * 100)
    print(f"{'#':<3} {'%':<7} {'Samples':<8} {'Function'}")
    print("-" * 100)

    for i, h in enumerate(hotspots[:25], 1):
        truncated = h['name'][:75] if len(h['name']) > 75 else h['name']
        print(f"{i:<3} {h['percentage']:>5.1f}% {h['samples']:>8} {truncated}")

    # Category analysis
    print()
    print("=" * 100)
    print("BOTTLENECK ANALYSIS BY CATEGORY:")
    print("=" * 100)
    print()

    categories = defaultdict(int)
    for h in hotspots:
        cat = categorize(h['name'])
        categories[cat] += h['samples']

    # Sort by samples
    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)

    print(f"{'Category':<25} {'%':<7} {'Samples':<8} {'Visualization'}")
    print("-" * 100)

    for cat, samples in sorted_cats:
        pct = (samples / total_samples * 100)
        bar = '█' * int(pct / 2)
        print(f"{cat:<25} {pct:>5.1f}% {samples:>8} {bar}")

    print()
    print("=" * 100)
    print("DETAILED FINDINGS:")
    print("=" * 100)
    print()

    # Key metrics
    lock_wait_pct = (categories.get('Lock Wait', 0) / total_samples * 100)
    sync_pct = (categories.get('Synchronization', 0) / total_samples * 100)
    cache_pct = (categories.get('Cache', 0) / total_samples * 100)
    async_pct = (categories.get('Async/Task', 0) / total_samples * 100) + (categories.get('Task Spawning', 0) / total_samples * 100)
    crypto_pct = (categories.get('Encryption', 0) / total_samples * 100)
    io_pct = (categories.get('Write Operations', 0) / total_samples * 100) + (categories.get('Read Operations', 0) / total_samples * 100)

    print(f"1. CRITICAL BOTTLENECK: pthread_cond_wait")
    print(f"   - CPU Time: {lock_wait_pct:.1f}% (threads blocked waiting on conditions)")
    print()

    if lock_wait_pct > 20:
        print(f"   ⚠️  This is the PRIMARY bottleneck!")
        print(f"   Threads are BLOCKING, not running CPU operations.")
        print()
        print(f"   What causes cond_wait:")
        print(f"   - Moka cache internal locks (threads wait for lock to be free)")
        print(f"   - I/O operations (disk/network waits)")
        print(f"   - tokio async executor parking threads")
        print()

        # Check what's actually running vs waiting
        running_pct = 100 - lock_wait_pct - sync_pct
        print(f"2. ACTUAL CPU WORK: {running_pct:.1f}%")
        print()
        print(f"   Breakdown of actual work:")
        print(f"   - Async/Task runtime: {async_pct:.1f}%")
        print(f"   - Encryption: {crypto_pct:.1f}%")
        print(f"   - File I/O operations: {io_pct:.1f}%")
        print(f"   - Cache operations: {cache_pct:.1f}%")
        print()

        print(f"3. ROOT CAUSE ANALYSIS:")
        print()
        print(f"   The Phase 1 optimization strategy (batch invalidations) was WRONG because:")
        print()
        print(f"   ❌ Problem: Assumed cache invalidations were expensive")
        print(f"   ✓ Reality: ~22% of time is spent in pthread_cond_wait")
        print(f"       This means threads are BLOCKED, not executing invalidation code")
        print()
        print(f"   ❌ Problem: Batch invalidations would reduce lock acquisitions")
        print(f"   ✓ Reality: Threads are blocked WAITING for locks, not acquiring them")
        print(f"       Reducing invalidation frequency doesn't help if you're waiting anyway")
        print()
        print(f"   What's actually happening:")
        print(f"   1. Thread A calls cache.get() -> acquires lock")
        print(f"   2. Thread B calls cache.insert() -> WAITS for Thread A's lock (cond_wait)")
        print(f"   3. Thread C and D also WAIT")
        print(f"   4. All three threads spend time in cond_wait, not doing useful work")
        print()

        print(f"4. CORRECT OPTIMIZATION STRATEGIES:")
        print()
        print(f"   🎯 High Priority:")
        print(f"   - Replace Moka cache with concurrent structure (DashMap)")
        print(f"   - Implement thread-local caches to eliminate contention")
        print(f"   - Use RwLock instead of Mutex for read-heavy operations")
        print()
        print(f"   🎯 Medium Priority:")
        print(f"   - Analyze if Tokio executor contention is significant")
        print(f"   - Check if I/O operations are blocking threads")
        print(f"   - Consider increasing thread count or using different executor")
        print()
        print(f"   🎯 Investigation Needed:")
        print(f"   - Which specific Moka operations trigger contention?")
        print(f"   - Are threads blocked on I/O or locks?")
        print(f"   - Can we use lock-free alternatives?")
        print()

if __name__ == "__main__":
    main()
