# TrueFoundry Reusable GitHub Workflows

A collection of reusable GitHub Actions workflows (`workflow_call`) for building and
publishing container images and for linting, scanning, testing, and documenting
Terraform/OpenTofu code.

Call any workflow from another repository:

```yaml
jobs:
  example:
    uses: truefoundry/github-workflows-public/.github/workflows/<workflow-file>.yml@main
    with:
      # inputs ...
    secrets:
      # secrets ...
```

---

## Workflows at a glance

| Workflow file                     | Name                                          | Purpose                                                              |
| --------------------------------- | --------------------------------------------- | ------------------------------------------------------------------- |
| `build.yml`                       | Build and push container images to Artifactory | Build a multi-platform image and push to JFrog Artifactory and/or AWS Public ECR |
| `build-and-push-soci-index.yml`   | Build and push SOCI index                     | Convert an existing pushed image into a SOCI index for lazy pulls   |
| `mirror-with-soci.yml`            | Mirror x86 image with SOCI index              | Mirror an `amd64` image from a source registry and push a SOCI index |
| `update-grype-report.yml`         | Update Grype Ignore File                      | Scan an image with Grype and open a PR updating the ignore list     |
| `terraform-lint-format.yml`       | Terraform fmt and linter                      | Check `terraform fmt` and run TFLint                                |
| `terraform-scan.yml`              | Iac code scanning                             | Scan IaC with Snyk                                                  |
| `terraform-test.yml`              | OpenTofu Test                                 | Run `tofu test` against `.tftest.hcl` files                         |
| `terraform-doc-generator.yml`     | Terraform doc generator                       | Generate and commit Terraform docs with `terraform-docs`            |

---

## Container image workflows

### `build.yml` — Build and push container images to Artifactory

Builds a multi-platform Docker image and pushes it to JFrog Artifactory and/or AWS Public
ECR. Optionally frees runner disk space, scans the `amd64` image with Anchore Grype before
pushing, applies extra tags, and emits provenance attestation. Uses a registry-based build
cache.

**Usage**

```yaml
jobs:
  build:
    uses: truefoundry/github-workflows-public/.github/workflows/build.yml@main
    with:
      artifactory_registry_url: tfy.jfrog.io
      artifactory_repository_url: tfy.jfrog.io/tfy-images
      image_artifact_name: mlfoundry-server
      image_tag: ${{ github.sha }}
      platforms: linux/amd64,linux/arm64
      enable_scan: true
    secrets:
      artifactory_username: ${{ secrets.ARTIFACTORY_USERNAME }}
      artifactory_password: ${{ secrets.ARTIFACTORY_PASSWORD }}
```

**Inputs**

| Name                                 | Description                                                            | Type    | Required | Default                  |
| ------------------------------------ | ---------------------------------------------------------------------- | ------- | -------- | ------------------------ |
| `artifactory_registry_url`           | Registry URL for JFrog Artifactory (e.g. `tfy.jfrog.io`)              | string  | false    |                          |
| `artifactory_repository_url`         | Repository URL for JFrog Artifactory (e.g. `tfy.jfrog.io/tfy-images`) | string  | false    |                          |
| `image_artifact_name`                | Name of the image artifact (usually the repo name)                    | string  | true     |                          |
| `image_tag`                          | Image tag for the image to be pushed                                  | string  | true     |                          |
| `extra_image_tag`                    | Extra image tag(s) for the image to be pushed                         | string  | false    |                          |
| `image_context`                      | Build context for the image                                           | string  | false    | `.`                      |
| `platforms`                          | Platforms to build for                                                | string  | false    | `linux/amd64,linux/arm64` |
| `enable_scan`                        | Enable image scanning (Grype)                                         | boolean | false    | `false`                  |
| `enable_public_ecr`                  | Enable push to AWS Public ECR                                         | boolean | false    | `false`                  |
| `ecr_repository_url`                 | Repository URL for AWS Public ECR (e.g. `public.ecr.aws/alias/repo`)  | string  | false    |                          |
| `enable_jfrog`                       | Enable push to JFrog Artifactory                                      | boolean | false    | `true`                   |
| `aws_ecr_region`                     | AWS Public ECR region                                                 | string  | false    | `us-east-1`              |
| `image_scan_severity_cutoff`         | Severity cutoff for image scanning                                    | string  | false    | `high`                   |
| `dockerfile_path`                    | Path to the Dockerfile                                                | string  | false    | `Dockerfile`             |
| `image_build_args`                   | Build-time arguments for Docker                                       | string  | false    |                          |
| `free_disk_space`                    | Free disk space on the runner                                         | boolean | false    | `false`                  |
| `free_disk_space_docker_images`      | Free disk space used by Docker images                                 | boolean | false    | `false`                  |
| `free_disk_space_tool_cache_storage` | Free disk space used by the tool cache                                | boolean | false    | `false`                  |
| `free_disk_space_large_packages`     | Free disk space used by large packages                                | boolean | false    | `false`                  |
| `enable_provenance`                  | Enable provenance attestation for supply-chain security               | boolean | false    | `false`                  |

**Secrets**

| Name                   | Description                                              | Required                    |
| ---------------------- | ------------------------------------------------------- | --------------------------- |
| `artifactory_username` | Username for JFrog Artifactory                          | Required if `enable_jfrog`  |
| `artifactory_password` | Password for JFrog Artifactory                          | Required if `enable_jfrog`  |
| `ecr_role_arn`         | Role ARN to pull/push images to AWS Public ECR          | Required if `enable_public_ecr` |

---

### `build-and-push-soci-index.yml` — Build and push SOCI index

Pulls an image that has already been pushed to the registry and converts it into a
[SOCI](https://github.com/awslabs/soci-snapshotter) index (for all requested platforms) to
enable lazy/seekable image pulls, then pushes the index back. Installs containerd `v2.2.0`,
nerdctl `v2.2.0`, and soci-snapshotter `v0.12.0`.

**Usage**

```yaml
jobs:
  soci:
    uses: truefoundry/github-workflows-public/.github/workflows/build-and-push-soci-index.yml@main
    with:
      artifactory_registry_url: tfy.jfrog.io
      artifactory_repository_url: tfy.jfrog.io/tfy-images
      image_artifact_name: mlfoundry-server
      image_tag: ${{ github.sha }}
    secrets:
      artifactory_username: ${{ secrets.ARTIFACTORY_USERNAME }}
      artifactory_password: ${{ secrets.ARTIFACTORY_PASSWORD }}
```

**Inputs**

| Name                                 | Description                                                            | Type    | Required | Default                  |
| ------------------------------------ | ---------------------------------------------------------------------- | ------- | -------- | ------------------------ |
| `artifactory_registry_url`           | Registry URL for JFrog Artifactory (e.g. `tfy.jfrog.io`)              | string  | true     |                          |
| `artifactory_repository_url`         | Repository URL for JFrog Artifactory (e.g. `tfy.jfrog.io/tfy-images`) | string  | true     |                          |
| `image_artifact_name`                | Name of the image artifact (usually the repo name)                    | string  | true     |                          |
| `enable_public_ecr`                  | Enable push to AWS Public ECR                                         | boolean | false    | `false`                  |
| `aws_ecr_region`                     | AWS Public ECR region                                                 | string  | false    | `us-east-1`              |
| `image_tag`                          | Image tag for the image to be pushed                                  | string  | true     |                          |
| `platforms`                          | Platforms for the image to be mirrored                                | string  | false    | `linux/amd64,linux/arm64` |
| `free_disk_space`                    | Free disk space on the runner                                         | boolean | false    | `false`                  |
| `free_disk_space_docker_images`      | Free disk space used by Docker images                                 | boolean | false    | `false`                  |
| `free_disk_space_tool_cache_storage` | Free disk space used by the tool cache                                | boolean | false    | `false`                  |
| `free_disk_space_large_packages`     | Free disk space used by large packages                                | boolean | false    | `false`                  |

**Secrets**

| Name                   | Description            | Required                        |
| ---------------------- | ---------------------- | ------------------------------- |
| `artifactory_username` | Artifactory username   | false                           |
| `artifactory_password` | Artifactory password   | false                           |
| `ecr_role_arn`         | Role ARN for AWS Public ECR | Required if `enable_public_ecr` |

---

### `mirror-with-soci.yml` — Mirror x86 image with SOCI index

Mirrors a `linux/amd64` image from a source registry into a target Artifactory repository,
converting it to a SOCI index along the way. Uses the same toolchain as
`build-and-push-soci-index.yml` (containerd `v2.2.0`, nerdctl `v2.2.0`, soci-snapshotter
`v0.12.0`) but is scoped to `linux/amd64` only.

**Usage**

```yaml
jobs:
  mirror:
    uses: truefoundry/github-workflows-public/.github/workflows/mirror-with-soci.yml@main
    with:
      source_registry: docker.io
      source_image: library/nginx:1.27
      artifactory_repository_url: tfy.jfrog.io/tfy-images
    secrets:
      artifactory_username: ${{ secrets.ARTIFACTORY_USERNAME }}
      artifactory_password: ${{ secrets.ARTIFACTORY_PASSWORD }}
```

**Inputs**

| Name                                 | Description                                                  | Type    | Required | Default |
| ------------------------------------ | ------------------------------------------------------------ | ------- | -------- | ------- |
| `source_registry`                    | Source registry for the image to be mirrored (e.g. `docker.io`) | string  | true     |         |
| `source_image`                       | Image URI to be mirrored (e.g. `a/b:tag`)                    | string  | true     |         |
| `artifactory_repository_url`         | Target registry/repository for the mirrored image            | string  | true     |         |
| `free_disk_space`                    | Free disk space on the runner                                | boolean | false    | `false` |
| `free_disk_space_docker_images`      | Free disk space used by Docker images                        | boolean | false    | `false` |
| `free_disk_space_tool_cache_storage` | Free disk space used by the tool cache                       | boolean | false    | `false` |
| `free_disk_space_large_packages`     | Free disk space used by large packages                       | boolean | false    | `false` |

**Secrets**

| Name                   | Description          | Required |
| ---------------------- | -------------------- | -------- |
| `artifactory_username` | Artifactory username | true     |
| `artifactory_password` | Artifactory password | true     |

---

### `update-grype-report.yml` — Update Grype Ignore File

Builds and loads an `amd64` image locally, scans it with Anchore Grype, runs a Python helper
to update the Grype ignore list in your config file, and opens a pull request (via
`peter-evans/create-pull-request@v5`) if the config changed.

**Usage**

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
      grype_config_file: .grype.yaml
      grype_output_file: vulnerability-report.json
      grype_output_format: json
```

**Inputs**

| Name                         | Description                                                                  | Type    | Required | Default                     |
| ---------------------------- | ---------------------------------------------------------------------------- | ------- | -------- | --------------------------- |
| `artifactory_repository_url` | Repository URL for JFrog Artifactory (e.g. `tfy.jfrog.io/tfy-images`)        | string  | true     |                             |
| `image_artifact_name`        | Name of the image artifact (usually the repo name)                           | string  | true     |                             |
| `dockerfile_path`            | Path to the Dockerfile                                                       | string  | false    | `Dockerfile`                |
| `image_build_args`           | Build-time arguments for Docker                                              | string  | false    |                             |
| `image_context`              | Build context for the image                                                  | string  | false    | `.`                         |
| `image_scan_severity_cutoff` | Minimum severity level to include in the scan                                | string  | false    | `critical`                  |
| `grype_fail_build`           | Fail the job if Grype finds vulnerabilities above the cutoff                 | boolean | false    | `false`                     |
| `grype_config_file`          | Path to the Grype config (moved to/from `.grype.yaml` during scanning)       | string  | false    | `.grype.yaml`               |
| `grype_output_file`          | Filename for the scan report                                                 | string  | false    | `vulnerability-report.json` |
| `grype_output_format`        | Output format for the scan report (`json`, `table`, `cyclonedx`, etc.)       | string  | false    | `json`                      |

**Permissions**

The caller must grant write access so the workflow can push the branch and open a PR:

```yaml
permissions:
  contents: write
```

**Note**

The `anchore/scan-action` does not yet support a custom config path. Until
[anchore/scan-action#427](https://github.com/anchore/scan-action/pull/427) is merged, this
workflow temporarily moves a custom `grype_config_file` to `.grype.yaml` for scanning and
reverts it afterward.

---

## Terraform / OpenTofu workflows

### `terraform-lint-format.yml` — Terraform fmt and linter

Runs two jobs: a `terraform fmt --recursive --diff -check=true` formatting check, and a
(conditional) TFLint job across an `ubuntu` / `macos` / `windows` matrix with plugin caching.

**Usage**

```yaml
jobs:
  lint:
    uses: truefoundry/github-workflows-public/.github/workflows/terraform-lint-format.yml@main
    with:
      terraform_version: 1.9.8
      enable_tflint: true
      tflint_severity_threshold: warning
```

**Inputs**

| Name                        | Description                                                       | Type    | Required | Default     |
| --------------------------- | ----------------------------------------------------------------- | ------- | -------- | ----------- |
| `terraform_version`         | Version of the Terraform binary                                   | string  | false    | `1.9.8`     |
| `enable_tflint`             | Enable TFLint                                                     | boolean | false    | `true`      |
| `tflint_severity_threshold` | Minimum failure severity for TFLint (`error` \| `warning` \| `notice`) | string  | false    | `warning`   |
| `tflint_version`            | TFLint version                                                   | string  | false    | `v0.53.0`   |

---

### `terraform-scan.yml` — Iac code scanning

Scans infrastructure-as-code with Snyk (`snyk/actions/iac@0.4.0`) at the configured severity
threshold.

**Usage**

```yaml
jobs:
  scan:
    uses: truefoundry/github-workflows-public/.github/workflows/terraform-scan.yml@main
    with:
      enable_code_test: true
      code_test_severity_threshold: high
    secrets:
      snyk_token: ${{ secrets.SNYK_TOKEN }}
```

**Inputs**

| Name                           | Description                                                | Type    | Required | Default |
| ------------------------------ | ---------------------------------------------------------- | ------- | -------- | ------- |
| `enable_code_test`             | Enable the Snyk code test                                  | boolean | false    | `true`  |
| `code_test_severity_threshold` | Severity threshold for IaC scanning (`low` \| `medium` \| `high`) | string  | false    | `high`  |

**Secrets**

| Name         | Description | Required |
| ------------ | ----------- | -------- |
| `snyk_token` | Snyk token  | true     |

---

### `terraform-test.yml` — OpenTofu Test

Sets up OpenTofu, runs `tofu init -backend=false`, then runs `tofu test` against the
`.tftest.hcl` files in the configured test directory.

**Usage**

```yaml
jobs:
  test:
    uses: truefoundry/github-workflows-public/.github/workflows/terraform-test.yml@main
    with:
      opentofu_version: 1.10.0
      working_directory: .
      test_directory: tests
```

**Inputs**

| Name                | Description                                                        | Type   | Required | Default |
| ------------------- | ----------------------------------------------------------------- | ------ | -------- | ------- |
| `opentofu_version`  | Version of the OpenTofu binary                                    | string | false    | `1.10.0` |
| `working_directory` | Directory containing the Terraform/OpenTofu module                | string | false    | `.`     |
| `test_directory`    | Directory containing the `.tftest.hcl` files (relative to `working_directory`) | string | false    | `tests` |

---

### `terraform-doc-generator.yml` — Terraform doc generator

Checks out the given commit ref and runs `terraform-docs/gh-actions` to generate/render
Terraform documentation, committing the changes back when `git_push` is enabled.

**Usage**

```yaml
jobs:
  docs:
    uses: truefoundry/github-workflows-public/.github/workflows/terraform-doc-generator.yml@main
    with:
      commit_ref: ${{ github.head_ref }}
      git_push: "true"
```

**Inputs**

| Name         | Description                                            | Type   | Required | Default  |
| ------------ | ------------------------------------------------------ | ------ | -------- | -------- |
| `commit_ref` | Commit ref where the README action should update      | string | true     |          |
| `git_push`   | Allow document changes to be pushed to `commit_ref`    | string | false    | `"true"` |

---

## Helper scripts

Some workflows rely on helper scripts in this repo:

- `.github/scripts/get-vulnerabilities.py` — used by `update-grype-report.yml` to update the
  Grype ignore list from a scan report.
- `.github/scripts/requirements.txt` — Python dependencies for the helper script.

---

## License

MIT © TrueFoundry
