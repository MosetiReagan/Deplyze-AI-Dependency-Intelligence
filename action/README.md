# Deplyze GitHub Action

Runs Deplyze in CI and uploads the SARIF report to GitHub code scanning.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: deplyze/deplyze/action@v1
    with:
      fail-on: high
      format: sarif
```

## Inputs

| Input          | Default         | Description                                |
| -------------- | --------------- | ------------------------------------------ |
| `path`         | `.`             | Project directory to analyse.              |
| `fail-on`      | `high`          | Severity threshold that fails the job.     |
| `format`       | `sarif`         | `terminal`, `json`, `markdown` or `sarif`. |
| `output`       | `deplyze.sarif` | Report path, relative to the project root. |
| `version`      | `latest`        | Deplyze version to install.                |
| `upload-sarif` | `true`          | Upload the report to code scanning.        |
| `args`         | `''`            | Extra arguments for `deplyze ci`.          |

## Outputs

| Output      | Description                                |
| ----------- | ------------------------------------------ |
| `exit-code` | `0` pass, `1` policy violation, `2` error. |

The action always uploads SARIF before failing, so a violation still produces annotations on the pull
request. It never leaks secrets: Deplyze does not require any tokens, and the action adds none.
