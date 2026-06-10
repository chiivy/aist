# Security Policy

## Supported Versions

AIST is currently in active development. 
Security fixes are applied to the latest version only.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in AIST, 
please do not open a public GitHub issue.

Report it privately by emailing the maintainer 
or using GitHub's private vulnerability reporting:

1. Go to github.com/chiivy/aist
2. Click the Security tab
3. Click "Report a vulnerability"

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

You will receive a response within 72 hours.

## What To Report

Security issues specific to AIST include:

- Second order prompt injection vulnerabilities 
  in AIST's own response processing pipeline
- Credential or API key exposure in logs or reports
- Authentication bypass in multi-user deployments
- Report tampering vulnerabilities
- Dependency vulnerabilities with direct impact

## What Not To Report

- Vulnerabilities in target agents discovered 
  during legitimate testing. That is what 
  AIST is designed to find.
- General prompt injection techniques. 
  These are documented intentionally 
  in the payload library.

## Disclosure Policy

Once a vulnerability is reported:

1. We confirm receipt within 72 hours
2. We investigate and develop a fix
3. We release the fix
4. We publicly disclose after fix is released

We follow responsible disclosure principles 
and credit reporters in release notes 
unless they request anonymity.scription of the vulnerability
-