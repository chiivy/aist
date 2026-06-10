"""
AIST Command Line Interface

Entry point for all AIST commands.

Commands:
    aist scan       Run a full security scan
    aist discover   Run attack surface discovery only

Usage:
    aist scan --target https://agent.example.com
              --tools email,files,database
              --output report.html
              --mode active
              --runs 3

    aist discover --target https://agent.example.com
                  --mode passive
                  --output surface-map.html
"""
