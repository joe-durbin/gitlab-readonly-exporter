# GitLab read-only exporter

`gitlab_export.py` exports selected GitLab REST API metadata to a new local directory of JSON files. It supports project IDs/paths and group IDs/paths, uses Python 3.9+ and the standard library, and makes read-only `GET` requests. It collects evidence; it does not analyse findings or assess security.

## Requirements and access

- Python 3.9 or later.
- Network access to the GitLab instance.
- A personal access token with the `read_api` scope, provided as `GITLAB_TOKEN` or `--token`.
- **The token's user must have Maintainer privileges** on each project and group to collect the full set of settings and metadata. Lower access levels, inherited permissions, GitLab edition, or instance configuration can restrict individual endpoints; such endpoints are recorded with their HTTP status rather than represented as empty results. Some API endpoints may impose additional role or tier requirements.

Use a token from an account authorised to access the requested scope. Command-line arguments may be recorded in shell history or visible to local process-inspection tools; prefer secure environment injection. Avoid sharing process listings or terminal history if using `--token`.

PowerShell example for loading a token without putting it in the command line:

```powershell
$secure = Read-Host "GitLab token" -AsSecureString
$env:GITLAB_TOKEN = [System.Net.NetworkCredential]::new("", $secure).Password
```

Clear it when finished:

```powershell
Remove-Item Env:GITLAB_TOKEN
```

## Usage

Collect selected projects:

```powershell
python .\gitlab_export.py --project group/subgroup/project --project 12345 --output .\exports\assessment
```

Collect a group and its directly included projects:

```powershell
python .\gitlab_export.py --group group/subgroup --output .\exports\assessment
```

Include projects from subgroups:

```powershell
python .\gitlab_export.py --group group/subgroup --include-subgroups --output .\exports\assessment
```

For a self-managed instance:

```powershell
python .\gitlab_export.py --base-url https://gitlab.example.org --group security/platform-access --output .\exports\gitlab-review
```

The base URL can also be set with `GITLAB_URL`. The output path must not already exist; existing directories are never overwritten. Status messages are written to standard error; the final JSON summary is written to standard output. Run local checks without credentials or network access:

```powershell
python .\gitlab_export.py --self-test
```

## Collected data

Project exports include project metadata; branches, tags and protection settings; approval settings and rules; environments and deployments; schedules; hook metadata without destinations; access/deploy-token metadata; merge-request, pipeline, job, commit and release metadata; package/container-registry inventory; runner metadata; job-token scope and allowlists; and membership aggregates by role and state. Group exports include group metadata, project inventory, membership aggregates, runners, protected branches/environments, hooks, token metadata and subgroups.

Each collection records endpoint HTTP status and pagination completeness where applicable. The root `manifest.json` records requested scope, timestamps, collection results, safety measures and limitations. A 2xx status does not guarantee that every control is visible; interpret the export in light of API permissions and GitLab configuration.

## Safety and limitations

- Only HTTP `GET` requests are issued. The script does not make changes to GitLab.
- Project/group CI variable endpoints are not called because they return variable values. No variable or secret values are requested or stored.
- Hook URLs and custom hook headers are excluded; membership is aggregated and user identities are not retained.
- Job traces/logs, artifact payloads, cache contents and repository file contents are not downloaded.
- Runner and token responses are filtered to explicit metadata fields; executor settings and authentication/configuration secrets are omitted.
- Collection is limited by token permissions, API availability, pagination, GitLab edition and instance configuration. An HTTP error means an endpoint could not be collected; it does not prove that a feature or control is absent.
- Inherited group/instance controls may not be visible through project-level endpoints. Confirm effective settings with an appropriately authorised owner.
- Treat exported metadata and identifiers as confidential. Store them only in an authorised location, follow applicable retention rules, and redact them before sharing.
- Use only against GitLab instances and scopes for which you are authorised. Validate evidence independently; this tool is not a penetration test or security assessment.
