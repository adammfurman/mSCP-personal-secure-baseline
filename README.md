# macOS Security Compliance Baseline

A custom CIS/NIST-aligned security hardening baseline for macOS Tahoe, built with the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (mSCP). Includes a compliance scan and full remediation to 100% passing.

## Overview

This project uses the mSCP Python tooling to author a custom YAML baseline, generate a compliance audit script, scan the system, and remediate every failing control. The baseline targets a personal workstation threat model with rules drawn from NIST 800-53 and CIS Benchmark controls.


## Requirements

- macOS Tahoe
- Python 3
    - required dependencies from mSCP
- `git`

## Usage

**1. Clone mSCP**

```sh
git clone https://github.com/usnistgov/macos_security.git
cd macos_security
```

**2. Install Python dependencies**

```sh
pip3 install -r requirements.txt
```

**3. Generate the audit script from the custom baseline**

```sh
python3 generate_guidance.py -b baselines/macOS-personal.yaml
```

**4. Run the compliance scan**

```sh
sudo ./build/macOS-personal/macOS_personal_compliance.sh
```

**5. Apply remediations and re-run until compliant**

## Baseline

The custom baseline is defined in `baselines/macOS-personal.yaml`. Rules were selected based on relevance to a personal workstation and alignment with my own risk-based decision framework:
- [risk-based-decision-framework.md]

## References

- [macOS Security Compliance Project — NIST](https://github.com/usnistgov/macos_security)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)