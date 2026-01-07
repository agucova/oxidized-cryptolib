#!/usr/bin/env python3
import re
import sys

def extract_metrics(filename):
    """Extract mean and sigma from benchmark output"""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        
        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_content = ansi_escape.sub('', content)
        
        # Look for pattern: "Time (mean ± σ):  5.09 s ± 11.71 ms"
        # The ± might be encoded differently, so match more flexibly
        match = re.search(r'Time.*?mean.*?(\d+\.\d+)\s*([a-z]+).*?(\d+\.\d+)\s*([a-z]+)', clean_content, re.DOTALL)
        if match:
            mean_val = float(match.group(1))
            mean_unit = match.group(2)
            sigma_val = float(match.group(3))
            sigma_unit = match.group(4)
            
            # Convert to milliseconds
            if mean_unit == 's':
                mean_ms = mean_val * 1000
            elif mean_unit == 'ms':
                mean_ms = mean_val
            else:
                return None
                
            if sigma_unit == 'ms':
                sigma_ms = sigma_val
            elif sigma_unit == 's':
                sigma_ms = sigma_val * 1000
            else:
                sigma_ms = sigma_val
                
            return (mean_ms, sigma_ms)
    except Exception as e:
        print(f"Error reading {filename}: {e}", file=sys.stderr)
    return None

# Compare baseline vs Phase1
workloads = ['concurrent', 'media', 'backup']
print("=" * 80)
print("PHASE 1 OPTIMIZATION RESULTS")
print("=" * 80)
print()

for workload in workloads:
    baseline_file = f'benchmarks/baseline-{workload}.txt'
    phase1_file = f'benchmarks/phase1-{workload}.txt'
    
    baseline = extract_metrics(baseline_file)
    phase1 = extract_metrics(phase1_file)
    
    if baseline and phase1:
        baseline_mean, baseline_sigma = baseline
        phase1_mean, phase1_sigma = phase1
        improvement_pct = ((baseline_mean - phase1_mean) / baseline_mean) * 100
        improvement_ms = baseline_mean - phase1_mean
        
        print(f"{workload.upper()}")
        print("-" * 80)
        print(f"  Baseline:  {baseline_mean:7.2f} ms ± {baseline_sigma:6.2f} ms")
        print(f"  Phase 1:   {phase1_mean:7.2f} ms ± {phase1_sigma:6.2f} ms")
        print(f"  Change:    {improvement_ms:7.2f} ms ({improvement_pct:+6.2f}%)")
        print()
    else:
        print(f"{workload.upper()}: Could not extract metrics")
        if baseline:
            print(f"  Baseline: {baseline}")
        if phase1:
            print(f"  Phase 1: {phase1}")
        print()

print("=" * 80)
