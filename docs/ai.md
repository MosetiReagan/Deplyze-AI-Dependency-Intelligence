# AI features

AI in Deplyze is an **optional explanation layer on top of deterministic analysis**. Deplyze is fully
functional with `ai.enabled: false`; every AI-assisted command has a deterministic fallback.

## Enabling AI

```yaml
# .deplyze.yml
ai:
  enabled: true
  provider: openai # openai | anthropic | gemini | ollama | http
  model: gpt-4o-mini
  apiKeyEnv: OPENAI_API_KEY # the NAME of the env var, never the key itself
  maxTokens: 1500
  temperature: 0.2
  redact: true
  maxFindings: 25
```

```bash
export OPENAI_API_KEY=...      # or DEPLYZE_AI_API_KEY
deplyze explain DEP-1234ABCD --ai
deplyze remediate --ai
deplyze upgrade-plan --ai
deplyze ai-review
```

Without `--ai`, `deplyze explain` prints a deterministic explanation. Without a configured provider,
AI commands fail with a clear message and a non-zero exit code; they never silently degrade.

## Providers

| Provider          | `ai.provider` | Default base URL                                   | Key env vars                                             |
| ----------------- | ------------- | -------------------------------------------------- | -------------------------------------------------------- |
| OpenAI-compatible | `openai`      | `https://api.openai.com/v1`                        | `DEPLYZE_AI_API_KEY`, `OPENAI_API_KEY`                   |
| Anthropic         | `anthropic`   | `https://api.anthropic.com/v1`                     | `DEPLYZE_AI_API_KEY`, `ANTHROPIC_API_KEY`                |
| Gemini            | `gemini`      | `https://generativelanguage.googleapis.com/v1beta` | `DEPLYZE_AI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY` |
| Ollama (local)    | `ollama`      | `http://127.0.0.1:11434`                           | none                                                     |
| Generic HTTP      | `http`        | `ai.baseUrl` (required)                            | `DEPLYZE_AI_API_KEY`                                     |

`ai.baseUrl` overrides the default for any provider, which is how self-hosted and gateway endpoints
are supported. Only `http:`/`https:` URLs are accepted.

## What is sent

`minimizeContext()` builds the smallest useful prompt:

- project name, manager and workspace count;
- graph statistics and the category risk scores;
- for at most `ai.maxFindings` findings (highest severity first): id, category, severity, confidence,
  title, package, version, advisory id, up to six short evidence strings, the remediation summary and
  at most two dependency paths.

Source code, file contents, environment variables and the full dependency tree are **never** sent.
The prompt records a `disclosure` line describing exactly what was transmitted, and the CLI prints it.

## Safety controls

- **Secrets are redacted** from prompts, provider error details and logs.
- **Untrusted metadata is fenced** (`<<<UNTRUSTED-DATA ... UNTRUSTED-DATA>>>`) and the model is told
  to treat it strictly as data. Embedded fence markers are filtered.
- **Provider errors are sanitised**, so a failing endpoint cannot echo a key back into your terminal.
- **No tool use.** The model only returns text; Deplyze never lets a model choose a command to run.
- **Deterministic findings win.** AI text is labelled as AI-generated and is never the source of a
  finding, a score or an exit code.
