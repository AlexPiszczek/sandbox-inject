# Contributing

Thanks for your interest in `sandbox-inject`. This is a small proof-of-concept
published alongside security research, so contributions are welcome but scoped.

## Ground rules

- This is **authorized-testing tooling**. Contributions must not add
  functionality whose primary purpose is to attack third parties, evade
  detection for malicious ends, or otherwise facilitate abuse. Keep changes
  aligned with defensive research and authorized testing.
- Be respectful and constructive. This project follows the
  [Code of Conduct](CODE_OF_CONDUCT.md).

## Good contributions

- Bug fixes (e.g., compatibility with newer SDK or sandbox runtime versions).
- Robustness improvements and clearer error handling.
- Documentation improvements.
- Detection / mitigation guidance for defenders.

## Reporting bugs

Open a GitHub issue describing:

- what you ran (command line), and against what kind of target;
- what you expected vs. what happened;
- your Python version and the installed `google-cloud-aiplatform` version.

Do **not** include real project numbers, resource IDs, access tokens, or other
sensitive identifiers in issues or pull requests.

## Pull requests

1. Fork the repository and create a feature branch.
2. Keep changes focused; one logical change per PR.
3. Match the existing style (standard library first, lazy SDK imports, clear
   `--flag` help text).
4. Verify the tool still runs (`sandbox_inject.py payloads`, `--help` on each
   subcommand) before submitting.
5. Do not commit test artifacts, credentials, or environment-specific files.

## Security issues

Please report security issues in the tool privately — see
[SECURITY.md](SECURITY.md) — rather than opening a public issue.
