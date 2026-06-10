"""
AIST Confidence Scoring

Calculates confidence level for each finding
based on consistency across multiple test runs.

Because language models are non-deterministic,
running each test case multiple times and
aggregating results produces more reliable
findings than a single run.
"""
