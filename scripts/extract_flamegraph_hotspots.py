#!/usr/bin/env python3
"""
Extract hottest functions from flamegraph SVG to identify bottlenecks.

Flamegraph width corresponds to CPU time: wider = more CPU time spent.
"""

import xml.etree.ElementTree as ET
import re
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple

def extract_flamegraph_data(svg_path: Path) -> List[Tuple[str, float]]:
    """
    Extract function names and their relative widths from flamegraph SVG.

    Flamegraph encodes CPU time in SVG element widths:
    - Wide rectangles = more CPU time
    - Title text has format: "function_name (samples)"
    """
    try:
        tree = ET.parse(svg_path)
        root = tree.getroot()

        # Extract all text elements which contain function names
        function_times = defaultdict(float)

        # Namespace for SVG
        ns = {'svg': 'http://www.w3.org/2000/svg'}

        # Find all <title> elements (which contain the full function name and sample count)
        for title_elem in root.findall('.//svg:title', ns):
            # Get the text content
            func_text = title_elem.text
            if func_text:
                # Remove newlines and clean up
                func_text = func_text.strip()

                # Extract sample count from format like "function (123 samples, 12.34%)"
                # Inferno format: "function_name (samples samples, percentage%)"
                match = re.search(r'\((\d+) samples', func_text)
                if match:
                    samples = int(match.group(1))
                    # Remove samples info to get clean function name
                    func_name = re.sub(r'\s*\(\d+ samples.*$', '', func_text)
                    function_times[func_name] += samples

        # Sort by time spent (descending)
        sorted_functions = sorted(
            function_times.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_functions
    except Exception as e:
        print(f"Error parsing {svg_path}: {e}")
        return []

def categorize_function(func_name: str) -> str:
    """Categorize function by type for analysis."""
    name_lower = func_name.lower()

    if any(x in name_lower for x in ['pthread', 'cond_wait', 'wait', 'lock', 'mutex', 'futex']):
        return 'Lock/Sync'
    elif any(x in name_lower for x in ['moka', 'cache', 'evict', 'insert']):
        return 'Cache'
    elif any(x in name_lower for x in ['read', 'write', 'getattr', 'lookup', 'stat']):
        return 'FUSE Ops'
    elif any(x in name_lower for x in ['encrypt', 'decrypt', 'aes', 'gcm', 'siv', 'crypto']):
        return 'Crypto'
    elif any(x in name_lower for x in ['tokio', 'spawn', 'task', 'executor', 'park']):
        return 'Async Runtime'
    elif any(x in name_lower for x in ['dashmap', 'dash', 'hashmap', 'map']):
        return 'Data Structure'
    elif any(x in name_lower for x in ['arc', 'clone', 'drop']):
        return 'Memory'
    else:
        return 'Other'

def main():
    """Analyze flamegraphs."""
    svg_file = Path('profiles/fuse_Folder_Browse.svg')

    if not svg_file.exists():
        print(f"Flamegraph not found: {svg_file}")
        return

    print("=" * 80)
    print("FLAMEGRAPH HOTSPOT ANALYSIS: Concurrent Access Workload")
    print("=" * 80)
    print()

    functions = extract_flamegraph_data(svg_file)

    if not functions:
        print("Could not extract function data from flamegraph")
        return

    total_samples = sum(count for _, count in functions)

    print(f"Total samples: {total_samples}\n")

    # Show top 20 functions
    print("TOP 20 HOTTEST FUNCTIONS:")
    print("-" * 80)
    print(f"{'Rank':<4} {'%':<6} {'Function':<50} {'Samples':<10}")
    print("-" * 80)

    for i, (func_name, samples) in enumerate(functions[:20], 1):
        percentage = (samples / total_samples * 100)
        print(f"{i:<4} {percentage:>5.1f}% {func_name:<50} {samples:>10}")

    # Categorized analysis
    print()
    print("=" * 80)
    print("BOTTLENECK ANALYSIS BY CATEGORY:")
    print("=" * 80)

    categories = defaultdict(int)
    for func_name, samples in functions:
        category = categorize_function(func_name)
        categories[category] += samples

    # Sort by total time
    sorted_categories = sorted(
        categories.items(),
        key=lambda x: x[1],
        reverse=True
    )

    print()
    for category, samples in sorted_categories:
        percentage = (samples / total_samples * 100)
        bar = '█' * int(percentage / 2)
        print(f"{category:<20} {percentage:>5.1f}% {bar}")

    print()
    print("=" * 80)
    print("KEY FINDINGS:")
    print("=" * 80)

    # Analyze patterns
    lock_sync_pct = (categories.get('Lock/Sync', 0) / total_samples * 100) if total_samples > 0 else 0
    cache_pct = (categories.get('Cache', 0) / total_samples * 100) if total_samples > 0 else 0
    crypto_pct = (categories.get('Crypto', 0) / total_samples * 100) if total_samples > 0 else 0
    fuse_ops_pct = (categories.get('FUSE Ops', 0) / total_samples * 100) if total_samples > 0 else 0
    async_pct = (categories.get('Async Runtime', 0) / total_samples * 100) if total_samples > 0 else 0

    print(f"""
Lock/Sync overhead: {lock_sync_pct:.1f}%
  - High values suggest lock contention (mutex waits, condition variables)

Cache overhead: {cache_pct:.1f}%
  - Moka internal locks, cache eviction, memory management

Crypto overhead: {crypto_pct:.1f}%
  - Encryption/decryption of files and filenames

FUSE Operations: {fuse_ops_pct:.1f}%
  - Filesystem operation handling (read, write, lookup, stat)

Async Runtime: {async_pct:.1f}%
  - Tokio executor, task scheduling, polling

INTERPRETATION:
""")

    if lock_sync_pct > 30:
        print(f"  ⚠️  High lock contention ({lock_sync_pct:.1f}%) - pthread_cond_wait dominates")
        print("     Likely causes:")
        print("     - Moka cache internal locks under concurrent access")
        print("     - Multiple threads waiting on same cache structure")
        print("     - Not a problem with invalidation frequency (Phase 1 was wrong target)")

    if cache_pct > 15 and cache_pct > crypto_pct:
        print(f"  💾 Cache layer is significant bottleneck ({cache_pct:.1f}%)")
        print("     Possible solutions:")
        print("     - Thread-local caches to reduce contention")
        print("     - RwLock instead of Mutex for read-heavy access")
        print("     - Different cache implementation (DashMap-based)")

    if crypto_pct > 20:
        print(f"  🔐 Crypto operations significant ({crypto_pct:.1f}%)")
        print("     Possible solutions:")
        print("     - Parallelize encryption (SIMD)")
        print("     - Cache encrypted filenames more aggressively")
        print("     - Batch crypto operations")

    if fuse_ops_pct > 20:
        print(f"  📁 FUSE operations significant ({fuse_ops_pct:.1f}%)")
        print("     Check which operation types dominate:")
        print("     - getattr/stat operations are usually slow (require directory cache lookup)")
        print("     - read/write are normally fast (direct crypto, no lookup)")

    if async_pct > 20:
        print(f"  ⚡ Async runtime overhead significant ({async_pct:.1f}%)")
        print("     Possible causes:")
        print("     - Task scheduling contention under 4 concurrent threads")
        print("     - Executor lock contention")
        print("     Solution: Consider different runtime or thread pool tuning")

if __name__ == "__main__":
    main()
