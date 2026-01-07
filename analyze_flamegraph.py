#!/usr/bin/env python3
"""Analyze flamegraph SVG to identify hot code paths."""

import re
import sys
from collections import defaultdict
from pathlib import Path

def parse_flamegraph(svg_path):
    """Extract function samples from flamegraph SVG."""
    with open(svg_path) as f:
        content = f.read()

    # Extract all <g> elements with title (function name) and width (samples)
    # Pattern: <g class="func_g" ... ><title>function_name (samples, percentage)</title>...width="N"
    pattern = r'<title>([^<]+?)\s+\((\d+(?:\.\d+)?)\s+samples?,\s+([\d.]+)%\)</title>'

    matches = re.findall(pattern, content)

    # Parse into list of (function_name, samples, percentage)
    functions = []
    for func_name, samples_str, pct_str in matches:
        try:
            samples = float(samples_str)
            pct = float(pct_str)
            functions.append((func_name, samples, pct))
        except ValueError:
            continue

    return functions

def categorize_functions(functions):
    """Group functions by subsystem."""
    categories = defaultdict(lambda: {'samples': 0, 'functions': []})

    for func, samples, pct in functions:
        # Determine category
        if 'fuser::' in func or 'fuse_' in func:
            category = 'FUSE Layer'
        elif 'oxcrypt_core::' in func or 'oxcrypt_' in func:
            category = 'Crypto Core'
        elif 'encrypt' in func.lower() or 'decrypt' in func.lower():
            category = 'Encryption/Decryption'
        elif 'aes' in func.lower() or 'gcm' in func.lower() or 'siv' in func.lower():
            category = 'AES Primitives'
        elif 'tokio::' in func or 'async' in func.lower():
            category = 'Async Runtime'
        elif 'std::io' in func or '::fs::' in func:
            category = 'I/O Operations'
        elif 'dashmap' in func.lower() or 'cache' in func.lower():
            category = 'Caching'
        elif 'lock' in func.lower() or 'mutex' in func.lower():
            category = 'Synchronization'
        else:
            category = 'Other'

        categories[category]['samples'] += samples
        categories[category]['functions'].append((func, samples, pct))

    return categories

def print_analysis(functions, top_n=20):
    """Print analysis of hot code paths."""
    # Sort by samples descending
    sorted_funcs = sorted(functions, key=lambda x: x[1], reverse=True)

    print(f"\n{'='*80}")
    print(f"TOP {top_n} HOTTEST FUNCTIONS")
    print(f"{'='*80}\n")

    for i, (func, samples, pct) in enumerate(sorted_funcs[:top_n], 1):
        # Shorten function name if too long
        display_name = func if len(func) <= 70 else func[:67] + '...'
        print(f"{i:2}. {pct:5.1f}%  {samples:8.0f} samples  {display_name}")

    print(f"\n{'='*80}")
    print("BREAKDOWN BY SUBSYSTEM")
    print(f"{'='*80}\n")

    categories = categorize_functions(functions)
    total_samples = sum(f[1] for f in functions)

    sorted_cats = sorted(categories.items(), key=lambda x: x[1]['samples'], reverse=True)

    for category, data in sorted_cats:
        pct = (data['samples'] / total_samples * 100) if total_samples > 0 else 0
        print(f"{category:25s}: {pct:5.1f}% ({data['samples']:8.0f} samples)")

        # Show top 3 functions in this category
        top_funcs = sorted(data['functions'], key=lambda x: x[1], reverse=True)[:3]
        for func, samples, func_pct in top_funcs:
            display_name = func if len(func) <= 60 else func[:57] + '...'
            print(f"  └─ {func_pct:4.1f}%  {display_name}")
        print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python analyze_flamegraph.py <flamegraph.svg>")
        sys.exit(1)

    svg_path = Path(sys.argv[1])
    if not svg_path.exists():
        print(f"Error: File not found: {svg_path}")
        sys.exit(1)

    print(f"Analyzing flamegraph: {svg_path}")

    functions = parse_flamegraph(svg_path)
    print(f"Found {len(functions)} unique function samples")

    print_analysis(functions)
