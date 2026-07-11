# ADR 002: Architecture Overview

## Status
Accepted

## Context
The framework must support hundreds of independent checks, multiple data sources, and diverse output formats while maintaining performance and code quality.

## Decision

### Layered Architecture

```
CLI Layer (Typer)
    |
Orchestration Layer (Runner)
    |
+---+---+---+---+---+---+
|   |   |   |   |   |   |
v   v   v   v   v   v   v
Collectors -> Checks -> Findings -> Scoring -> Reporting
    ^                        |
    |                        v
    +----- Cache ----------+
```

### Layer Responsibilities

1. **CLI Layer**: User interaction, command parsing, output display
2. **Orchestration Layer**: Plugin discovery, dependency resolution, parallel execution, caching
3. **Collectors**: Efficient data gathering (one pass per data source)
4. **Checks**: Pure analysis functions consuming collector output
5. **Findings**: Structured results with evidence
6. **Scoring**: Weighted risk calculation
7. **Reporting**: Output formatting (terminal, JSON, Markdown, etc.)
8. **Cache**: Avoid repeated expensive operations
9. **Configuration**: YAML-based policy management

### Key Design Rules

- Collectors never analyze. Checks never collect.
- Findings never format themselves. Reporters never create findings.
- No circular dependencies between layers.
- Every layer depends only on models or abstractions.
- Plugin discovery uses namespace packages with registration.

## Consequences
- Clean testability: each layer can be tested independently
- Parallel execution: checks can run in parallel when dependencies are met
- Performance: one subprocess call per data source, not per check
- Extensibility: new checks need zero changes to core
