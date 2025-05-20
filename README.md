**Update Grype Ignore File Workflow**

A reusable GitHub Actions workflow that:

1. **Builds** a Docker image for vulnerability scanning.
2. **Ensures** a Grype configuration (`.grype.yaml` or custom path) exists.
3. **Scans** the image with Anchore’s Grype action.
4. **Restores** any custom config file path.
5. **Updates** your Grype ignore list via a Python helper script.
6. **Opens** a pull request with the updated ignore file if changes are detected.

---

## How to Use

Call this workflow from another repository or workflow via `workflow_call`:

```yaml
name: Auto-update Grype Ignore

on:
  schedule:
    - cron: '0 3 * * *'   # daily at 03:00 UTC

jobs:
  update-grype:
    uses: truefoundry/github-workflows-public/.github/workflows/update-grype-report.yml@main
    with:
      artifactory_repository_url: tfy.jfrog.io/tfy-images
      image_artifact_name: my-app-server
      dockerfile_path: Dockerfile
      image_context: .
      image_scan_severity_cutoff: high
      grype_fail_build: false
      grype_config_file: .grype.yaml      # optional, defaults to .grype.yaml
      grype_output_file: vulnerability-report.json
      grype_output_format: json
```

This will run the scan, update the ignore list in `.grype.yaml` (or your custom path), and create a PR if there are new ignores.

---

## Inputs

| Name                         | Description                                                                             | Required | Default                     |
| ---------------------------- | --------------------------------------------------------------------------------------- | -------- | --------------------------- |
| `artifactory_repository_url` | URL of your JFrog Artifactory repository (e.g. `tfy.jfrog.io/tfy-images`)               | true     |                             |
| `image_artifact_name`        | Name of the Docker image (e.g. `mlfoundry-server`)                                      | true     |                             |
| `dockerfile_path`            | Path to the `Dockerfile`                                                                | false    | `Dockerfile`                |
| `image_context`              | Build context for Docker                                                                | false    | `.`                         |
| `image_build_args`           | Build-time arguments for Docker                                                         | false    | (none)                      |
| `image_scan_severity_cutoff` | Minimum severity level to include in the scan                                           | false    | `critical`                  |
| `grype_fail_build`           | Fail the job if Grype finds vulnerabilities above the cutoff                            | false    | `false`                     |
| `grype_config_file`          | Path to a custom Grype config (will be moved to and from `.grype.yaml` during scanning) | false    | `.grype.yaml`               |
| `grype_output_file`          | Filename for the scan report                                                            | false    | `vulnerability-report.json` |
| `grype_output_format`        | Output format for the scan report (`json`, `table`, `cyclonedx`, etc.)                  | false    | `json`                      |

---

## Permissions

This workflow requires:

```yaml
permissions:
  contents: write          # to push changes and open PRs
  id-token: write (optional) # if using OIDC for cloud auth
```

Also ensure your caller passes a token (e.g. `workflow_repo_token`) with write rights to the target repo.

---

## Workflow Steps

1. **Checkout** your repository and the shared `github-workflows-public` scripts.
2. **Set up** Docker Buildx and Python.
3. **Build & load** the Docker image tagged as `:grype-report`.
4. **Prepare** `.grype.yaml`:

    * Move a custom config into place or create an empty stub if missing.
5. **Scan** the image with `anchore/scan-action@v6`.
6. **Revert** `.grype.yaml` back to the original path (if custom).
7. **Install** Python deps and run `get-vulnerabilities.py` to update the ignore list in your config file.
8. **Diff** the config file; if changed, **open** a PR using `peter-evans/create-pull-request@v5`.

---

## Customization

* **Scheduling**: call this from a separate workflow with a `schedule` trigger to automate daily or weekly updates.
* **Severity cutoff**: adjust `image_scan_severity_cutoff` to `medium`, `low`, etc., as needed.
* **Fail-fast**: set `grype_fail_build: true` to break the pipeline on critical findings.
* **Scripts path**: if you move `get-vulnerabilities.py`, update the `pip install` and script invocation paths.

---

## Notes
There is a PR for custom config path for the anchore/scan-action. Until it is merged, the workflow will temporarily move the custom config to `.grype.yaml` for scanning and revert it back after.
A [PR](https://github.com/anchore/scan-action/pull/427) has been raised to the `anchore/scan-action` repo to support custom config paths.

## License

MIT © TrueFoundry
