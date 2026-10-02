# Security Policy

> **English · 中文**

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use the following channel:

- **GitHub Security Advisories** (only channel): open a
  [private security advisory](https://github.com/InterTraveler/BurpAuditAI/security/advisories/new)
  so we can fix and coordinate disclosure together.

Please include the following:

- A clear description of the vulnerability and its impact.
- A proof-of-concept or reproduction steps (Burp project file is fine;
  **do not include real targets or credentials**).
- The BurpAuditAI version, Burp Suite version, JDK version, and OS.
- Whether you intend public disclosure and any preferred timeline.

We will acknowledge your report within **5 business days** and aim to ship
a fix or mitigation within **30 days** for high-severity issues. We will
coordinate disclosure timing with you.

## Threat Model & Scope

BurpAuditAI is a **local Burp Suite extension** that:

- Reads HTTP traffic visible to Burp (Proxy / Repeater / Intruder / etc.).
- Sends **selected** traffic to a user-configured AI endpoint
  (after default header redaction and binary-body truncation).
- Stores per-project traffic metadata in
  `<burp-install>/AuditAIData/projects/<projectId>/` (or fallbacks).
- Persists configuration and an XOR-obfuscated API key in Montoya
  `Preferences`.

The following are explicitly **out of scope** for security reports:

- Bugs in third-party libraries — please report upstream
  (Montoya API / Gson / JUnit).
- Misconfiguration of your own AI endpoint (e.g. an unprotected
  self-hosted Ollama instance).
- Vulnerabilities in Burp Suite itself (report to PortSwigger).
- Social engineering or phishing of maintainers.

## Built-in Privacy Mitigations

These mitigations are **on by default**; please don't disable them
without good reason:

| Mitigation | Where |
| :--- | :--- |
| `Authorization` / `Cookie` / `Set-Cookie` header redaction before sending to LLM | `com.auditai.burp.util.TextUtil#redactHeaderValue` |
| Binary body truncation above 256 KiB (body replaced with size-only placeholder) | `com.auditai.burp.util.TrafficCompactor` |
| Text body truncation above 1 MiB | `TrafficCompactor` |
| Per-string JSON field cap of 64 KiB | `TrafficCompactor` |
| `montoya-api` excluded from the fat JAR (avoids classpath conflicts and accidental API shadowing) | `pom.xml` (`maven-shade-plugin`) |
| API key stored XOR-obfuscated in Montoya `Preferences` (deters casual shoulder-surfing; **not** a cryptographic guarantee) | `com.auditai.burp.config.ApiKeyCipher` |

## Safe Usage Checklist

- [ ] Configure your AI endpoint to **TLS** (`https://...`); do not use
      plain HTTP for remote services.
- [ ] Use a **dedicated API key** with the minimum required scope
      (e.g. a project-scoped key for DeepSeek / OpenAI).
- [ ] Enable the redaction features — they are on by default; do not
      override them with custom prompt templates that ask the model to
      "echo back the headers".
- [ ] If you work in a regulated environment, **run a local model**
      (Ollama, LM Studio, vLLM) and never send traffic to a remote endpoint.
- [ ] Keep BurpAuditAI updated — watch releases for security advisories.
- [ ] File a [private security advisory](https://github.com/InterTraveler/BurpAuditAI/security/advisories/new)
      if you find a vulnerability.

## Security Hall of Fame

We are grateful to the researchers and contributors who have helped
improve BurpAuditAI's security. Reporters are listed here after a fix is
shipped and (with their consent) a public disclosure is published.

_No reports yet — be the first._

## 中文摘要

- **请勿**通过公开 issue 报告安全漏洞，仅通过 GitHub Security Advisories
  联系维护者。
- 默认开启的隐私保护：敏感请求头脱敏、二进制裁剪（256 KiB）、文本裁剪（1 MiB）、
  JSON 字段上限（64 KiB）、API Key XOR 混淆。
- 安全使用清单见上方 *Safe Usage Checklist*。
