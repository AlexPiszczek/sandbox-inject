# Support

`sandbox-inject` is a proof-of-concept provided **as-is** for defensive
research and authorized security testing. It is not a commercially supported
product, and there is no SLA.

## Getting help

- **Read the [README](README.md) first.** It covers requirements (Python
  3.9–3.13, the Vertex AI SDK, ADC login), the full command reference, and a
  "How it works" section.
- **Usage questions and bugs:** open a GitHub issue in this repository. Include
  the command you ran, what you expected, what happened, and your Python and
  `google-cloud-aiplatform` versions. Do not paste real project numbers,
  resource IDs, or credentials.
- **Security issues in the tool:** report privately per
  [SECURITY.md](SECURITY.md).

## Out of scope

- **Google Cloud / Vertex AI platform issues** — report to Google via
  [Google Bug Hunters / VRP](https://bughunters.google.com/).
- **Operational support for running attacks** — this project does not provide
  assistance with using the tool against systems you do not own or have
  permission to test.

## Background

For the full technical write-up and disclosure timeline, see the accompanying
blog post referenced in the README.
