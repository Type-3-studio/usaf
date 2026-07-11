# ADR 001: Project Goals and Scope

## Status
Accepted

## Context
The project aims to build a production-grade Ubuntu security auditing framework. It must serve security consultants, incident responders, DevOps engineers, and enterprise environments. The framework must feel like a professional security product rather than a script collection.

## Decision
Build `usaf` (Ubuntu Security Audit Framework) as:

1. A modular Python framework with strict separation of concerns
2. Plugin-based architecture where every audit is a plugin
3. Collector pattern to minimize redundant subprocess calls
4. Structured finding model with evidence, remediation, and threat intelligence mapping
5. Weighted risk scoring with category breakdowns
6. Multiple output formats (terminal, JSON, Markdown, HTML, SARIF, CSV)
7. Configuration-driven with YAML policies and profiles
8. Baseline comparison for drift detection
9. Designed for CI/CD integration and automation from day one

## Non-Goals
- Not a real-time monitoring agent (future scope)
- Not a vulnerability scanner (though CVE references included)
- Not a configuration management tool (Puppet/Ansible complement)
- Not an EDR (though compromise detection included)

## Consequences
- Clean separation enables independent development of checks
- Plugin system allows community contributions without core changes
- Collector pattern ensures performance at scale (hundreds of checks)
- Rich finding model enables precise, actionable reporting
- YAML configuration makes enterprise deployment straightforward
