# Security Policy

## Reporting a vulnerability

Please report security issues **privately** via GitHub's private vulnerability reporting
(the *Security → Report a vulnerability* tab of this repository). Do not open a public
issue for a security report.

You can expect an acknowledgement within a few days, followed by a fix or a mitigation
plan.

## Notes

- This is a standalone open-source tool with no hosted backend; it processes only the
  input you give it and does not transmit data anywhere except the documented endpoints.
- Secrets are kept out of the tree by a `gitleaks` scan that runs in CI on every push.
- Dependency advisories are welcome here, and should also be reported upstream.
