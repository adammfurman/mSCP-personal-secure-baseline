# macOS Security Compliance Baseline

A custom CIS/NIST-aligned security hardening baseline for macOS Tahoe, built with the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (mSCP). Includes a compliance scan and full remediation to 100% passing.

## Overview

This project uses the mSCP Python tooling to author a custom YAML baseline, generate a compliance audit script, scan the system, and remediate every failing control. The baseline targets a personal workstation threat model with rules drawn from NIST 800-53 and CIS Benchmark controls.

Files:
- baseline YAML: `baselines/macOS-personal.yaml`
- decision framework: `risk-based-decision-framework.md`
- compliance script: `build/macOS-personal/macOS_personal_compliance.sh`

## Requirements

- macOS Tahoe
- Python 3
    - required dependencies from mSCP
- `git`

## Baseline

The custom baseline is defined in `baselines/macOS-personal.yaml`. Rules were selected based on relevance to a personal workstation and alignment with my own risk-based decision framework:
- [risk-based-decision-framework.md]

## References

- [macOS Security Compliance Project — NIST](https://github.com/usnistgov/macos_security)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)