# Security Policy

## About this repository

This repository contains **`sandbox-inject`**, a proof-of-concept published for
defensive research and authorized security testing. It demonstrates a
response-channel injection technique in Google Vertex AI Agent Engine that was
reported to Google and assessed as *working as intended* (closed **Won't Fix**).
The full disclosure is described in the accompanying blog post.

Because the underlying behavior in Google's platform is not being patched by
the vendor, this PoC is intended to help defenders **detect and mitigate** the
issue in their own deployments (see "Detection & mitigation" in the
[README](README.md)).

## Reporting a vulnerability in this tool

If you discover a security issue **in this tool's own code** (for example, a
flaw that could harm a user running it), please report it privately rather than
opening a public issue:

- **Email:** apiszczek@beyondtrust.com
- Alternatively, use GitHub's **private vulnerability reporting** for this
  repository (Security → Report a vulnerability).

Please include a description, reproduction steps, and any relevant environment
details. You can expect an acknowledgement within a reasonable time frame.

## Reporting issues in Google Vertex AI

Vulnerabilities in **Google Cloud / Vertex AI** itself are out of scope for
this repository. Report those to Google through the
[Google Bug Hunters / VRP](https://bughunters.google.com/) program.

## Responsible use

This software is for authorized testing only. Use it exclusively against Google
Cloud projects and resources that you own or have explicit written permission
to test. See the [README](README.md) for the full terms of use.
