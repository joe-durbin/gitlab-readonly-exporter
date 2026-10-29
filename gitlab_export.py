#!/usr/bin/env python3
"""Read-only GitLab project/group metadata exporter (Python 3.9+, stdlib only).

The exporter saves review-oriented metadata to a new local output directory. It
never performs a non-GET request, downloads repositories/artifacts/logs, or reads
CI variable values. Set GITLAB_TOKEN in the environment; never pass tokens on
command lines or write them into the export.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


def report_status(message: str) -> None:
    print(f"[status] {message}", file=sys.stderr, flush=True)


API_VERSION = "v4"
USER_AGENT = "gitlab-readonly-exporter/1.0"
MAX_RETRIES = 4
PER_PAGE = 100

# Keep API results only after selecting non-secret, report-useful fields.
PROJECT_FIELDS = (
    "id", "name", "path", "path_with_namespace", "visibility", "archived",
    "default_branch", "created_at", "last_activity_at", "namespace", "topics",
    "repository_access_level", "merge_requests_access_level", "builds_access_level",
    "issues_access_level", "wiki_access_level", "container_registry_access_level",
    "package_registry_access_level", "security_and_compliance_access_level",
    "merge_method", "only_allow_merge_if_pipeline_succeeds",
    "only_allow_merge_if_all_discussions_are_resolved", "allow_merge_on_skipped_pipeline",
    "merge_pipelines_enabled", "merge_trains_enabled", "ci_config_path",
    "ci_pipeline_variables_minimum_override_role", "ci_allow_fork_pipelines_to_run_in_parent_project",
    "ci_job_token_scope_enabled", "ci_push_repository_for_job_token_allowed",
    "restrict_user_defined_variables", "shared_runners_enabled", "group_runners_enabled",
    "keep_latest_artifact", "ci_forward_deployment_enabled", "ci_forward_deployment_rollback_allowed",
    "container_registry_enabled", "packages_enabled", "forking_access_level",
)
RUNNER_FIELDS = (
    "id", "runner_type", "active", "paused", "online", "status", "run_untagged",
    "access_level", "tag_list", "created_at", "contacted_at", "version", "revision",
    "platform", "architecture", "maximum_timeout", "locked", "is_shared",
)
BRANCH_FIELDS = ("name", "default", "protected", "merged", "can_push", "can_merge", "developers_can_push", "developers_can_merge")
PROTECTED_BRANCH_FIELDS = ("name", "allow_force_push", "code_owner_approval_required", "push_access_levels", "merge_access_levels")
PROTECTED_TAG_FIELDS = ("name", "create_access_levels")
APPROVAL_FIELDS = (
    "approvals_before_merge", "reset_approvals_on_push", "disable_overriding_approvers_per_merge_request",
    "merge_requests_author_approval", "merge_requests_disable_committers_approval",
    "require_password_to_approve", "require_reauthentication_to_approve",
)
RULE_FIELDS = ("id", "name", "rule_type", "approvals_required", "applies_to_all_protected_branches", "protected_branches")
ENV_FIELDS = ("id", "name", "slug", "state", "created_at", "updated_at", "external_url")
DEPLOYMENT_FIELDS = ("id", "status", "created_at", "updated_at", "deployable", "environment")
SCHEDULE_FIELDS = ("id", "active", "cron", "cron_timezone", "created_at", "updated_at", "next_run_at", "last_pipeline")
HOOK_FIELDS = (
    "id", "created_at", "push_events", "tag_push_events", "merge_requests_events", "issues_events",
    "pipeline_events", "job_events", "wiki_page_events", "deployment_events", "enable_ssl_verification",
    "alert_status", "resource_access_token_events",
)
TOKEN_META_FIELDS = ("id", "name", "active", "revoked", "created_at", "expires_at", "scopes", "user_id", "last_used_at")
MR_FIELDS = (
    "id", "iid", "title", "state", "created_at", "updated_at", "merged_at", "closed_at",
    "target_branch", "source_branch", "draft", "work_in_progress", "merge_status", "detailed_merge_status",
    "approvals_before_merge", "user_notes_count", "has_conflicts", "blocking_discussions_resolved",
)
PIPELINE_FIELDS = ("id", "iid", "status", "source", "ref", "sha", "created_at", "updated_at", "started_at", "finished_at", "duration", "queued_duration", "web_url")
JOB_FIELDS = ("id", "name", "stage", "status", "ref", "created_at", "started_at", "finished_at", "erased_at", "artifacts_expire_at", "artifacts", "failure_reason", "allow_failure", "tag_list", "runner")
COMMIT_FIELDS = ("id", "short_id", "created_at", "parent_ids", "authored_date", "committed_date", "title", "author_name", "author_email", "committer_name", "committer_email", "web_url", "stats", "status")
RELEASE_FIELDS = ("tag_name", "name", "created_at", "released_at", "upcoming_release", "commit", "milestones")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_component(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._")
    return value[:100] or "item"


def select_fields(value: Any, fields: Iterable[str]) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in fields if key in value}


def safe_project(obj: dict[str, Any]) -> dict[str, Any]:
    result = select_fields(obj, PROJECT_FIELDS)
    # Retain only safe namespace identifiers; URLs/descriptions may contain private data.
    ns = result.get("namespace")
    if isinstance(ns, dict):
        result["namespace"] = {k: ns[k] for k in ("id", "name", "path", "kind", "full_path", "parent_id") if k in ns}
    return result


def safe_member_aggregate(members: list[dict[str, Any]]) -> dict[str, Any]:
    roles = Counter(str(m.get("access_level", "unknown")) for m in members)
    states = Counter(str(m.get("state", "unknown")) for m in members)
    return {"records": len(members), "role_counts_by_access_level": dict(sorted(roles.items())), "state_counts": dict(sorted(states.items())), "identities_retained": False}


def safe_hook(obj: dict[str, Any]) -> dict[str, Any]:
    # Deliberately exclude url, custom headers, descriptions and secret tokens.
    return select_fields(obj, HOOK_FIELDS)


def safe_runner(obj: dict[str, Any]) -> dict[str, Any]:
    return select_fields(obj, RUNNER_FIELDS)


def safe_deployment(obj: dict[str, Any]) -> dict[str, Any]:
    out = select_fields(obj, DEPLOYMENT_FIELDS)
    deployable = out.get("deployable")
    if isinstance(deployable, dict):
        out["deployable"] = {k: deployable[k] for k in ("id", "status", "name", "stage", "created_at", "finished_at", "ref") if k in deployable}
    env = out.get("environment")
    if isinstance(env, dict):
        out["environment"] = {k: env[k] for k in ("id", "name", "slug", "tier", "state") if k in env}
    return out


def safe_pipeline(obj: dict[str, Any]) -> dict[str, Any]:
    return select_fields(obj, PIPELINE_FIELDS)


def safe_job(obj: dict[str, Any]) -> dict[str, Any]:
    out = select_fields(obj, JOB_FIELDS)
    runner = out.get("runner")
    if isinstance(runner, dict):
        out["runner"] = {k: runner[k] for k in ("id", "runner_type", "status", "active", "paused", "tag_list", "access_level") if k in runner}
    artifacts = out.get("artifacts")
    if isinstance(artifacts, list):
        out["artifacts"] = [select_fields(a, ("file_type", "size", "filename", "file_format")) for a in artifacts if isinstance(a, dict)]
    return out


class GitLabAPI:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Base URL must be an http(s) URL without embedded credentials")
        self.base_url = base_url.rstrip("/")
        self.api = self.base_url + "/api/" + API_VERSION
        self.token = token
        self.timeout = timeout

    def get(self, path: str, query: dict[str, Any] | None = None) -> tuple[int, Any, dict[str, str]]:
        url = self.api + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        # Explicitly reject non-API URLs and paths that could escape the configured host.
        parsed = urllib.parse.urlsplit(url)
        if parsed.netloc != urllib.parse.urlsplit(self.api).netloc or not parsed.path.startswith("/api/v4/"):
            raise ValueError("Refusing request outside configured GitLab API")
        req = urllib.request.Request(url, method="GET", headers={"PRIVATE-TOKEN": self.token, "Accept": "application/json", "User-Agent": USER_AGENT})
        for attempt in range(MAX_RETRIES + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    payload = response.read()
                    data = json.loads(payload.decode("utf-8")) if payload else None
                    return response.status, data, {k.lower(): v for k, v in response.headers.items()}
            except urllib.error.HTTPError as exc:
                status = exc.code
                headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
                # Never retain response bodies from errors; they can echo sensitive request data.
                if status in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                    wait = headers.get("retry-after", "")
                    try:
                        delay = min(max(float(wait), 1.0), 60.0) if wait else min(2 ** attempt, 30)
                    except ValueError:
                        delay = min(2 ** attempt, 30)
                    report_status(f"Temporary API error (HTTP {status}); retrying in {delay:g}s ({attempt + 1}/{MAX_RETRIES}).")
                    time.sleep(delay)
                    continue
                return status, {"error": "HTTP request failed; response body intentionally omitted"}, headers
            except (TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
                if attempt < MAX_RETRIES:
                    delay = min(2 ** attempt, 30)
                    report_status(f"Request failed ({type(exc).__name__}); retrying in {delay}s ({attempt + 1}/{MAX_RETRIES}).")
                    time.sleep(delay)
                    continue
                return 0, {"error": type(exc).__name__}, {}
        return 0, {"error": "retry limit reached"}, {}

    def pages(self, path: str, extra_query: dict[str, Any] | None = None) -> tuple[int, list[Any], dict[str, Any]]:
        rows: list[Any] = []
        page = 1
        total_pages: int | None = None
        status = 0
        while True:
            query = dict(extra_query or {})
            query.update({"per_page": PER_PAGE, "page": page})
            status, data, headers = self.get(path, query)
            if status < 200 or status >= 300:
                return status, rows, {"pages_fetched": page - 1, "total_pages": total_pages, "pagination_complete": False, "error": data.get("error") if isinstance(data, dict) else "request failed"}
            if not isinstance(data, list):
                return status, rows, {"pages_fetched": page, "total_pages": total_pages, "pagination_complete": False, "error": "unexpected non-list response"}
            rows.extend(data)
            total_pages = int(headers["x-total-pages"]) if headers.get("x-total-pages", "").isdigit() else total_pages
            next_page = headers.get("x-next-page", "")
            if next_page.isdigit():
                page = int(next_page)
            elif total_pages is not None and page < total_pages:
                page += 1
            elif len(data) == PER_PAGE:
                page += 1
            else:
                return status, rows, {"pages_fetched": page, "total_pages": total_pages or page, "pagination_complete": True}
            if total_pages is not None and page > total_pages:
                return status, rows, {"pages_fetched": page - 1, "total_pages": total_pages, "pagination_complete": True}


def write_json(root: Path, relative: str, data: Any) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def collect_endpoint(api: GitLabAPI, root: Path, rel: str, path: str, transform=lambda x: x, query=None) -> dict[str, Any]:
    status, rows, pagination = api.pages(path, query)
    safe_rows = [transform(row) for row in rows]
    write_json(root, rel, {"http_status": status, "collected_at_utc": utc_now(), "pagination": pagination, "count": len(safe_rows), "items": safe_rows})
    return {"file": rel, "http_status": status, "count": len(safe_rows), **pagination}


def collect_single(api: GitLabAPI, root: Path, rel: str, path: str, transform=lambda x: x) -> dict[str, Any]:
    status, data, _ = api.get(path)
    result = transform(data) if 200 <= status < 300 else data
    write_json(root, rel, {"http_status": status, "collected_at_utc": utc_now(), "data": result})
    return {"file": rel, "http_status": status}


def collect_project(api: GitLabAPI, root: Path, project_ref: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(str(project_ref), safe="")
    report_status(f"Collecting project {project_ref}.")
    status, project, _ = api.get("/projects/" + encoded)
    if status < 200 or status >= 300 or not isinstance(project, dict):
        report_status(f"Project metadata unavailable for {project_ref} (HTTP {status}).")
        return {"project_ref": project_ref, "http_status": status, "error": "project metadata unavailable"}
    project_id = project.get("id")
    slug = safe_component(f"{project_id}_{project.get('path', project.get('name', 'project'))}")
    dest = root / "projects" / slug
    dest.mkdir(parents=True, exist_ok=True)
    write_json(dest, "project.json", {"http_status": status, "collected_at_utc": utc_now(), "data": safe_project(project)})
    results: list[dict[str, Any]] = [{"file": "project.json", "http_status": status}]
    p = f"/projects/{project_id}"
    # All calls are read-only. Variable values are never requested: the endpoint returns values, not metadata-only.
    endpoints = [
        ("branches.json", p + "/repository/branches", lambda x: select_fields(x, BRANCH_FIELDS)),
        ("protected_branches.json", p + "/protected_branches", lambda x: select_fields(x, PROTECTED_BRANCH_FIELDS)),
        ("protected_tags.json", p + "/protected_tags", lambda x: select_fields(x, PROTECTED_TAG_FIELDS)),
        ("approval_rules.json", p + "/approval_rules", lambda x: select_fields(x, RULE_FIELDS)),
        ("protected_environments.json", p + "/protected_environments", lambda x: select_fields(x, ("name", "deploy_access_levels"))),
        ("environments.json", p + "/environments", lambda x: select_fields(x, ENV_FIELDS)),
        ("deployments.json", p + "/deployments", safe_deployment),
        ("pipeline_schedules.json", p + "/pipeline_schedules", lambda x: select_fields(x, SCHEDULE_FIELDS)),
        ("hooks.json", p + "/hooks", safe_hook),
        ("deploy_tokens.json", p + "/deploy_tokens", lambda x: select_fields(x, TOKEN_META_FIELDS)),
        ("access_tokens.json", p + "/access_tokens", lambda x: select_fields(x, TOKEN_META_FIELDS)),
        ("merge_requests.json", p + "/merge_requests", lambda x: select_fields(x, MR_FIELDS), {"state": "all", "order_by": "updated_at", "sort": "desc"}),
        ("pipelines.json", p + "/pipelines", safe_pipeline),
        ("commits.json", p + "/repository/commits", lambda x: select_fields(x, COMMIT_FIELDS)),
        ("releases.json", p + "/releases", lambda x: select_fields(x, RELEASE_FIELDS)),
        ("packages.json", p + "/packages", lambda x: select_fields(x, ("id", "name", "version", "package_type", "created_at", "last_downloaded_at", "status"))),
        ("container_registry_repositories.json", p + "/registry/repositories", lambda x: select_fields(x, ("id", "name", "path", "location", "created_at", "cleanup_policy_started_at"))),
        ("project_runners.json", p + "/runners", safe_runner),
    ]
    report_status(f"Collecting project settings for {project.get('path_with_namespace', project_ref)} ({len(endpoints)} endpoint groups).")
    for item in endpoints:
        name, path, transform = item[:3]
        query = item[3] if len(item) > 3 else None
        results.append(collect_endpoint(api, dest, name, path, transform, query))
    # Non-list configuration endpoints. Never request CI variables or artifact/log payloads.
    results.append(collect_single(api, dest, "push_rule.json", p + "/push_rule", lambda x: select_fields(x, ("commit_message_regex", "commit_message_negative_regex", "branch_name_regex", "deny_delete_tag", "member_check", "prevent_secrets", "author_email_regex", "file_name_regex", "max_file_size", "commit_committer_check", "commit_committer_name_check", "reject_unsigned_commits", "reject_non_dco_commits"))))
    results.append(collect_single(api, dest, "approvals.json", p + "/approvals", lambda x: select_fields(x, APPROVAL_FIELDS)))
    results.append(collect_single(api, dest, "job_token_scope.json", p + "/job_token_scope", lambda x: select_fields(x, ("inbound_enabled", "outbound_enabled"))))
    results.append(collect_endpoint(api, dest, "job_token_project_allowlist.json", p + "/job_token_scope/allowlist", lambda x: select_fields(x, ("id", "name", "path", "path_with_namespace", "visibility"))))
    results.append(collect_endpoint(api, dest, "job_token_group_allowlist.json", p + "/job_token_scope/groups_allowlist", lambda x: select_fields(x, ("id", "name", "path", "full_path", "visibility"))))
    # Aggregate memberships in memory; do not persist user identities by default.
    code, members, page_info = api.pages(p + "/members/all")
    write_json(dest, "membership_summary.json", {"http_status": code, "collected_at_utc": utc_now(), "pagination": page_info, "summary": safe_member_aggregate([m for m in members if isinstance(m, dict)])})
    results.append({"file": "membership_summary.json", "http_status": code, "count": len(members), **page_info})
    # Runner details only contain fields on an explicit allowlist; no token/configuration fields are retained.
    runner_result = next((r for r in results if r["file"] == "project_runners.json"), None)
    runners_file = dest / "project_runners.json"
    try:
        runners = json.loads(runners_file.read_text(encoding="utf-8")).get("items", [])
    except (OSError, json.JSONDecodeError):
        runners = []
    detail_rows = []
    report_status(f"Collecting metadata for {len(runners)} project runners.")
    for runner in runners:
        if not isinstance(runner, dict) or not runner.get("id"):
            continue
        rs, rd, _ = api.get("/runners/" + urllib.parse.quote(str(runner["id"]), safe=""))
        detail_rows.append({"http_status": rs, "data": safe_runner(rd) if 200 <= rs < 300 and isinstance(rd, dict) else None})
    write_json(dest, "runner_details.json", {"collected_at_utc": utc_now(), "count": len(detail_rows), "items": detail_rows, "note": "Only allowlisted runner metadata retained; executor and authentication fields omitted."})
    results.append({"file": "runner_details.json", "count": len(detail_rows)})
    # List jobs for each visible pipeline to collect safe job/artifact metadata only; never fetch traces or artifacts.
    try:
        pipeline_data = json.loads((dest / "pipelines.json").read_text(encoding="utf-8"))
        pipelines = pipeline_data.get("items", [])
    except (OSError, json.JSONDecodeError):
        pipelines = []
    report_status(f"Collecting job metadata for {len(pipelines)} pipelines.")
    jobs: list[dict[str, Any]] = []
    job_statuses: list[dict[str, Any]] = []
    for pipeline in pipelines:
        if not isinstance(pipeline, dict) or not pipeline.get("id"):
            continue
        js, jrows, jinfo = api.pages(p + f"/pipelines/{pipeline['id']}/jobs")
        job_statuses.append({"pipeline_id": pipeline["id"], "http_status": js, "pagination": jinfo, "count": len(jrows)})
        jobs.extend(safe_job(row) for row in jrows if isinstance(row, dict))
    write_json(dest, "jobs_metadata.json", {"collected_at_utc": utc_now(), "pipeline_count": len(pipelines), "job_count": len(jobs), "pipeline_requests": job_statuses, "items": jobs, "note": "Job trace/log and artifact contents were not requested or downloaded."})
    results.append({"file": "jobs_metadata.json", "count": len(jobs)})
    write_json(dest, "collection_index.json", {"project": safe_project(project), "collected_at_utc": utc_now(), "endpoints": results, "safety": {"http_methods": ["GET"], "variable_values_requested": False, "secret_values_retained": False, "hook_urls_retained": False, "member_identities_retained": False, "job_logs_downloaded": False, "artifact_payloads_downloaded": False, "repository_file_contents_downloaded": False}})
    failed_endpoints = sum(1 for r in results if r.get("http_status", 200) < 200 or r.get("http_status", 200) >= 300)
    report_status(f"Finished project {project.get('path_with_namespace', project_ref)}: {len(results)} endpoints, {failed_endpoints} failed.")
    return {"project": project.get("path_with_namespace", project_ref), "id": project_id, "directory": str(dest), "endpoints": len(results), "failed_endpoints": failed_endpoints}


def collect_group(api: GitLabAPI, root: Path, group_ref: str, include_subgroups: bool) -> dict[str, Any]:
    encoded = urllib.parse.quote(str(group_ref), safe="")
    report_status(f"Collecting group {group_ref}.")
    status, group, _ = api.get("/groups/" + encoded)
    if status < 200 or status >= 300 or not isinstance(group, dict):
        report_status(f"Group metadata unavailable for {group_ref} (HTTP {status}).")
        return {"group_ref": group_ref, "http_status": status, "error": "group metadata unavailable"}
    group_id = group.get("id")
    slug = safe_component(f"{group_id}_{group.get('full_path', group.get('path', 'group'))}")
    dest = root / "groups" / slug
    dest.mkdir(parents=True, exist_ok=True)
    fields = ("id", "name", "path", "full_path", "visibility", "parent_id", "created_at", "default_branch_protection", "default_branch_protection_defaults", "shared_runners_setting", "prevent_forking_outside_group", "subgroup_creation_level", "project_creation_level", "require_two_factor_authentication", "share_with_group_lock")
    write_json(dest, "group.json", {"http_status": status, "collected_at_utc": utc_now(), "data": select_fields(group, fields)})
    q = {"with_shared": "true", "include_subgroups": "true" if include_subgroups else "false"}
    report_status(f"Collecting membership and project list for {group.get('full_path', group_ref)}.")
    members_status, members, member_page = api.pages(f"/groups/{group_id}/members/all")
    write_json(dest, "membership_summary.json", {"http_status": members_status, "collected_at_utc": utc_now(), "pagination": member_page, "summary": safe_member_aggregate([m for m in members if isinstance(m, dict)])})
    project_status, projects, project_page = api.pages(f"/groups/{group_id}/projects", q)
    safe_projects = [safe_project(x) for x in projects if isinstance(x, dict)]
    write_json(dest, "projects.json", {"http_status": project_status, "collected_at_utc": utc_now(), "pagination": project_page, "count": len(safe_projects), "items": safe_projects})
    results = []
    report_status(f"Collecting group settings for {group.get('full_path', group_ref)}.")
    for endpoint, transform in (
        ("runners", safe_runner),
        ("protected_branches", lambda x: select_fields(x, PROTECTED_BRANCH_FIELDS)),
        ("protected_environments", lambda x: select_fields(x, ("name", "deploy_access_levels"))),
        ("hooks", safe_hook),
        ("deploy_tokens", lambda x: select_fields(x, TOKEN_META_FIELDS)),
        ("access_tokens", lambda x: select_fields(x, TOKEN_META_FIELDS)),
        ("subgroups", lambda x: select_fields(x, ("id", "name", "path", "full_path", "visibility", "parent_id"))),
    ):
        results.append(collect_endpoint(api, dest, endpoint + ".json", f"/groups/{group_id}/{endpoint}", transform))
    project_refs = [x["id"] for x in safe_projects if x.get("id") is not None]
    group_info = {"group": select_fields(group, fields), "directory": str(dest), "projects_discovered": len(project_refs), "project_membership_endpoints": results}
    write_json(dest, "collection_index.json", group_info)
    report_status(f"Finished group {group.get('full_path', group_ref)}: {len(project_refs)} projects discovered.")
    return {"group": group.get("full_path", group_ref), "id": group_id, "directory": str(dest), "project_ids": project_refs, "projects_discovered": len(project_refs)}


def self_test() -> int:
    assert safe_component("../group/project") == "group_project"
    assert select_fields({"token": "never", "id": 7}, ("id",)) == {"id": 7}
    assert safe_hook({"url": "https://example.invalid/?token=secret", "id": 4, "push_events": True}) == {"id": 4, "push_events": True}
    assert safe_member_aggregate([{"access_level": 40, "username": "person", "state": "active"}]) == {"records": 1, "role_counts_by_access_level": {"40": 1}, "state_counts": {"active": 1}, "identities_retained": False}
    assert safe_job({"id": 1, "trace": "secret", "artifacts": [{"filename": "a.zip", "size": 42, "file_type": "archive", "file_format": "zip"}]}) == {"id": 1, "artifacts": [{"file_type": "archive", "size": 42, "filename": "a.zip", "file_format": "zip"}]}
    print("Self-test passed; no network requests made.")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export read-only GitLab group/project metadata to a local directory. Uses only GET requests.")
    p.add_argument("--base-url", default=os.environ.get("GITLAB_URL", "https://gitlab.com"), help="GitLab base URL (default: GITLAB_URL or https://gitlab.com)")
    p.add_argument("--project", action="append", default=[], help="Project ID or URL-encoded/unencoded namespace/path; repeatable")
    p.add_argument("--group", action="append", default=[], help="Group ID or path; repeatable. Discovers its projects.")
    p.add_argument("--include-subgroups", action="store_true", help="For --group, discover projects recursively in subgroups")
    p.add_argument("--output", required=False, help="New output directory; must not already exist")
    p.add_argument("--token", help="GitLab PAT (visible in shell history/process listings; prefer GITLAB_TOKEN environment variable)")
    p.add_argument("--self-test", action="store_true", help="Run local safety/serialization checks without credentials or network")
    p.add_argument("--timeout", type=int, default=30, help="Per-request timeout in seconds (default 30)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    if not args.project and not args.group:
        print("At least one --project or --group is required.", file=sys.stderr)
        return 2
    if not args.output:
        print("--output is required.", file=sys.stderr)
        return 2
    token = args.token or os.environ.get("GITLAB_TOKEN")
    if not token:
        print("Provide --token or set GITLAB_TOKEN in the environment.", file=sys.stderr)
        return 2
    out = Path(args.output).expanduser().resolve()
    if out.exists():
        print("Output path already exists; choose a new directory to avoid overwriting data.", file=sys.stderr)
        return 2
    if args.timeout < 1 or args.timeout > 600:
        print("--timeout must be between 1 and 600 seconds.", file=sys.stderr)
        return 2
    try:
        api = GitLabAPI(args.base_url, token, args.timeout)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report_status(f"Starting read-only collection from {api.base_url}.")
    out.mkdir(parents=True, exist_ok=False)
    started = utc_now()
    group_results = [collect_group(api, out, ref, args.include_subgroups) for ref in args.group]
    discovered = {str(pid) for g in group_results for pid in g.get("project_ids", [])}
    explicit = [str(x) for x in args.project]
    project_refs = list(dict.fromkeys(explicit + sorted(discovered)))
    report_status(f"Collecting {len(project_refs)} unique projects ({len(explicit)} explicitly requested, {len(discovered)} discovered from groups).")
    project_results = [collect_project(api, out, ref) for ref in project_refs]
    manifest = {
        "tool": "gitlab-readonly-exporter", "tool_version": "1.0", "started_at_utc": started,
        "finished_at_utc": utc_now(), "gitlab_base_url": api.base_url,
        "scope": {"groups_requested": args.group, "projects_requested": args.project, "include_subgroups": args.include_subgroups},
        "groups": group_results, "projects": project_results,
        "safety": {
            "http_methods": ["GET"], "variables_endpoint_not_called": True,
            "variable_values_or_secrets_retained": False, "hook_urls_or_custom_headers_retained": False,
            "member_identities_retained": False, "job_logs_or_traces_downloaded": False,
            "artifact_payloads_downloaded": False, "repository_file_contents_downloaded": False,
            "token_written_to_output": False,
        },
        "limitations": [
            "Collection is limited by the authenticated account's permissions and GitLab edition/configuration; failed endpoints are recorded by HTTP status.",
            "CI variable endpoints are not called because they return values; group and project variable values are not collected.",
            "Job traces, logs, artifact payloads, caches and repository file contents are not downloaded.",
            "Membership data is aggregated by role and state; personal identities are not retained.",
            "Protected controls inherited from ancestors or instance-wide settings may not be visible from project/group endpoints.",
            "This is an evidence collector, not a security assessment; validate findings and interpret control semantics separately.",
        ],
    }
    write_json(out, "manifest.json", manifest)
    failed_projects = sum(1 for result in project_results if result.get("failed_endpoints", 0) or result.get("error"))
    failed_groups = sum(1 for result in group_results if result.get("error"))
    report_status(f"Collection complete: {len(group_results)} groups, {len(project_results)} projects; issues in {failed_groups} groups and {failed_projects} projects.")
    print(json.dumps({"output_directory": str(out), "groups": len(group_results), "projects": len(project_results), "manifest": str(out / "manifest.json")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
