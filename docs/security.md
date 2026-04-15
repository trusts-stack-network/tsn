# Security

The `crypto` module is susceptible to several threats, including:

* Les timing attacks : the functions de cryptographie can be vulnerables to timing attacks si elles ne are pas correctly securees.
* Les data leaks : les private keys and les data sensibles must be protecteof the contre les data leaks.

To mitigate these threats, we use:

* Des fonctions de cryptographie securees contre les timing attacks.
* Des mechanisms de protection of the data pour prevent les data leaks.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Timing attacks | Fonctions de cryptographie securees contre les timing attacks |
| Data leaks | Mechanisms de protection of the data pour prevent les data leaks |

## Security Tests

Security tests are performed regularly to ensure the `crypto` module is secure. Tests include:

* Property tests for signatures, proofs, and commitments.
* Regression tests for each vulnerability.
* Fuzzers for external inputs.

## Responsible Disclosure Policy

Nous suivons une politique de divulgation responsable for vulnerabilities de security. Si vous discover une security vulnerability, veuillez nous contacter to the address [security@example.com](mailto:security@example.com).