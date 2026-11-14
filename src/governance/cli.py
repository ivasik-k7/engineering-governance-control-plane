from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from governance import __version__, bootstrap
from governance.catalog import CATALOG_ENV, build_catalog_document, import_backstage
from governance.changes import git_diff
from governance.decision import (
    SIGNING_KEY_ENV,
    DecisionError,
    LocalStore,
    S3ObjectLockStore,
    build_record,
    replay,
    verify_record,
)
from governance.design import validate_design
from governance.github import GitHubError, pr_approvals
from governance.identity import resolve_identity
from governance.lint import lint_registry
from governance.project import ProjectConfig, find_project_root, load_project, write_project
from governance.registry import (
    TRUSTED_KEYS_ENV,
    RegistryError,
    build_bundle,
    generate_keypair,
    load_registry,
)
from governance.resolver import applicable_rules_payload, resolve_context
from governance.sarif import to_sarif
from governance.session import Session, open_session, select_registry

EXIT_OK, EXIT_BLOCKED, EXIT_USAGE = 0, 1, 2
ICON = {
    "fail": "✗",
    "error": "!",
    "manual_review": "?",
    "waived": "~",
    "pass": "✓",
    "not_applicable": "-",
    "skipped": "-",
}


def _session(args: argparse.Namespace) -> Session:
    return open_session(getattr(args, "path", None) or ".", args.registry)


def _emit(data: Any, as_json: bool, text: str) -> None:
    print(json.dumps(data, indent=2, default=str) if as_json else text)


def cmd_profile_detect(args: argparse.Namespace) -> int:
    session = _session(args)
    ctx = session.context(environment=args.environment)
    d = ctx.to_dict()
    lines = [
        f"project:     {d['project']}",
        f"identity:    {d['identity']['id']} ({'verified' if d['identity']['verified'] else 'unverified'}, "
        f"{d['identity']['source']})",
        f"profiles:    {', '.join(d['profiles']) or '(none matched)'}",
        f"environment: {d['environment']}",
        f"languages:   {', '.join(d['languages']) or '-'}",
        f"frameworks:  {', '.join(d['frameworks']) or '-'}",
        f"platforms:   {', '.join(d['platforms']) or '-'}",
    ]
    lines += [f"warning: {x.get('message') or x}" for x in d["diagnostics"]]
    _emit(d, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_rules_list(args: argparse.Namespace) -> int:
    session = _session(args)
    reg = session.registry
    if args.all:
        rules = [r.summary() for r in reg.rules.values()]
        _emit(
            rules,
            args.json,
            "\n".join(
                f"{r['id']:<9} {r['level']:<6} {r['severity']:<8} {r['category']:<12} {r['title']}" for r in rules
            ),
        )
        return EXIT_OK
    ctx = session.context(task=args.task or "", environment=args.environment, paths=args.file)
    payload = applicable_rules_payload(reg, ctx, limit=args.limit)
    lines = [
        f"policy {payload['policy_version']} | profiles: {', '.join(payload['profiles']) or '-'} | "
        f"env: {payload['environment']} | tasks: {', '.join(payload['tasks']) or '-'}",
        "",
    ]
    lines += [f"{r['id']:<9} {r['level']:<6} {r['severity']:<8} {r['title']}" for r in payload["rules"]]
    if payload["other_mandatory"]:
        lines.append("")
        lines.append("Also mandatory for this repository (not targeted by this change):")
        lines += [f"  {r['id']:<9} {r['level']:<6} {r['title']}" for r in payload["other_mandatory"]]
    if payload["omitted"]["count"]:
        lines.append(f"... {payload['omitted']['count']} lower-relevance rule(s) omitted; use --limit")
    for c in payload["conflicts"]:
        lines.append(f"{c['type']}: {c['message']}")
    for d in payload["diagnostics"]:
        lines.append(f"warning: {d.get('message') or d}")
    _emit(payload, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_rules_explain(args: argparse.Namespace) -> int:
    reg = _session(args).registry
    rule = reg.rule(args.rule_id)
    if args.json:
        _emit({**rule.summary(), "content": rule.body}, True, "")
    else:
        print(f"{rule.id} [{rule.enforcement.label}/{rule.severity.value}] {rule.title}  (v{rule.version})")
        print(
            f"owner: {rule.owner} | layer: {rule.layer} | validator: {rule.validation.ref} | "
            f"waivers: {'allowed' if rule.waiver_allowed else 'not allowed'}\n"
        )
        print(rule.body)
    return EXIT_OK


def _format_report(report: dict[str, Any], verbose: bool) -> str:
    ev, s = report["evidence"], report["summary"]
    out = [
        f"engineering-governance | policy {ev['policy_version']} | {ev['project']} | "
        f"profiles: {', '.join(ev['profiles']) or '-'} | env: {ev['environment']} | mode: {ev['mode']}",
        f"identity: {ev['identity']['id']} ({'verified' if ev['identity']['verified'] else 'unverified'}) | "
        f"registry: {ev['registry']['source']}, "
        f"{'signed by ' + signer if (signer := ev['registry']['verified_by']) else 'unsigned'}",
        f"{s['files_checked']} file(s), {s['rules_evaluated']} rule(s) evaluated",
        "",
    ]
    for r in report["results"]:
        if r["status"] in ("not_applicable", "skipped", "pass") and not verbose:
            continue
        tag = "BLOCKING" if r["blocking"] else r["status"].upper()
        out.append(f"{ICON[r['status']]} {r['rule_id']:<9} {r['level']:<6} {tag:<14} {r['title']}")
        for f in r["findings"]:
            out.append(f"    {f['file']}:{f['line_start']}  {f['message']}")
            if f["snippet"]:
                out.append(f"        {f['snippet']}")
        for f in r.get("waived_findings", []):
            out.append(f"    {f['file']}:{f['line_start']}  (waived by {f['waiver']}) {f['message']}")
        if r["status"] in ("error", "skipped") and r.get("detail"):
            out.append(f"    {r['detail']}")
    for c in s["policy_conflicts"]:
        out.append(f"! policy_conflict: {c['message']}")
    for g in s["coverage_gaps"]:
        examples = f" (e.g. {', '.join(g['examples'][:3])})" if g.get("examples") else ""
        out.append(f"! coverage gap: {g['message']}{examples}")
    for d in report["diagnostics"]:
        out.append(f"warning: {d.get('message') or d}")
    out += ["", f"verdict: {report['verdict']} | evidence: {report['evidence_grade']}"]
    for reason in ev["grade_reasons"]:
        out.append(f"  advisory because: {reason}")
    if s["unverified_mandatory"]:
        out.append(f"not verified (HARD): {', '.join(s['unverified_mandatory'])}; do not claim compliance")
    if s["manual_review_required"]:
        out.append(f"manual review required: {', '.join(s['manual_review_required'])}")
    for ob in report.get("obligations", []):
        missing = [r["reviewer"] for r in ob["reviewers"] if not r["approved"]]
        missing += [f"artefact {a['id']} ({', '.join(a['paths'][:2])})" for a in ob["artefacts"] if not a["satisfied"]]
        state = "satisfied" if ob["status"] == "satisfied" else "pending: " + ", ".join(missing)
        out.append(f"obligation {ob['id']} [{ob['enforcement']}] {ob['title']} - {state}")
    if report.get("controls"):
        fw = ", ".join(
            f"{name} " + "/".join(f"{k}={v}" for k, v in sorted(d["statuses"].items()))
            for name, d in report["controls"]["frameworks"].items()
        )
        out.append(f"controls: {fw}")
    return "\n".join(out)


def cmd_validate(args: argparse.Namespace) -> int:
    session = _session(args)
    today = dt.date.today()
    approvals = {a.strip() for a in (args.approved_by or "").split(",") if a.strip()}
    if args.github_pr:
        token = os.environ.get("GITHUB_TOKEN", "")
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        if not token or not repository:
            print("error: --github-pr needs GITHUB_TOKEN and GITHUB_REPOSITORY", file=sys.stderr)
            return EXIT_USAGE
        teams = {r for ob in session.registry.obligations for r in ob.reviewers if "/" in r}
        try:
            approvals |= pr_approvals(
                repository,
                args.github_pr,
                token,
                teams,
                os.environ.get("GOV_PR_HEAD_SHA"),
                os.environ.get("GOV_GITHUB_TOKEN"),
            )
        except GitHubError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    options = {
        "fail_closed": args.fail_closed,
        "strict": args.strict,
        "run_external": not args.no_external,
        "today": today,
        "approvals": approvals,
        "enforce_obligations": args.enforce_obligations,
    }
    context = {"task": args.task or "", "environment": args.environment}
    if args.diff:
        diff_text = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(encoding="utf-8")
        evaluation = session.evaluate_diff(diff_text, **context, **options)
    elif args.base or args.changed:
        try:
            diff_text = git_diff(session.root, args.base or "HEAD")
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"error: git diff failed: {exc}", file=sys.stderr)
            return EXIT_USAGE
        evaluation = session.evaluate_diff(diff_text, **context, **options)
    else:
        evaluation = session.evaluate_repository(**context, **options)
    report = evaluation.report
    reg = session.registry

    if args.record or args.store or args.s3_bucket:
        record = build_record(
            reg,
            evaluation.context,
            report,
            evaluation.fileset,
            evaluated_on=today,
            sign_key=Path(args.sign_key) if args.sign_key else None,
        )
        if args.record:
            Path(args.record).write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        locations = [args.record] if args.record else []
        try:
            if args.store:
                locations.append(LocalStore(args.store).write(record))
            if args.s3_bucket:
                store = S3ObjectLockStore(args.s3_bucket, args.s3_prefix, args.retention_days, args.lock_mode)
                locations.append(store.write(record))
        except DecisionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        signed = f", signed by {record['signatures'][0]['key_id']}" if record["signatures"] else ", unsigned"
        print(f"decision record {record['decision_id']}{signed}: {', '.join(locations)}", file=sys.stderr)

    if args.format == "json":
        rendered = json.dumps(report, indent=2)
    elif args.format == "sarif":
        rendered = json.dumps(to_sarif(report, reg), indent=2)
    else:
        rendered = _format_report(report, args.verbose)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"verdict: {report['verdict']} (report written to {args.output})")
    else:
        print(rendered)
    if report["verdict"] == "fail":
        return EXIT_BLOCKED
    if args.require_authoritative and report["evidence_grade"] != "authoritative":
        print(
            "error: --require-authoritative: evidence is advisory: " + "; ".join(report["evidence"]["grade_reasons"]),
            file=sys.stderr,
        )
        return EXIT_USAGE
    return EXIT_OK


def cmd_rules_why(args: argparse.Namespace) -> int:
    session = _session(args)
    d = session.explain(args.rule_id, task=args.task or "", environment=args.environment, paths=args.file)
    lines = [
        f"{d['rule_id']} {d['title']} (v{d['rule_version']})",
        f"outcome: {d['outcome']}" + (f" | enforcement: {d['enforcement']}" if d["applied"] else ""),
        f"context: env={d['context']['environment']} tasks={','.join(d['context']['tasks']) or '-'} "
        f"profiles={','.join(d['context']['profiles']) or '-'}",
        "",
    ]
    lines += [f"  {c['code']:<28} {c['detail']}" for c in d["checks"]]
    lines += [f"  {c['code']:<28} {c['detail']}" for c in d["enforcement_trace"]]
    if d["waivers"]:
        lines.append(f"  waivers: {', '.join(d['waivers'])}")
    if d["superseded_by"]:
        lines.append(f"  superseded by {d['superseded_by']}")
    _emit(d, args.json, "\n".join(lines))
    return EXIT_OK


def _load_record(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_decision_verify(args: argparse.Namespace) -> int:
    result = verify_record(_load_record(args.record))
    _emit(
        result,
        args.json,
        f"{result['decision_id']}: {'valid' if result['valid'] else 'INVALID'}"
        + (f", signed by {result['signed_by']}" if result["signed_by"] else ", signature not verified")
        + "".join(f"\n  {p}" for p in result["problems"]),
    )
    return EXIT_OK if result["valid"] else EXIT_BLOCKED


def cmd_decision_replay(args: argparse.Namespace) -> int:
    record = _load_record(args.record)
    try:
        result = replay(record, load_registry(args.registry))
    except DecisionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    text = (
        f"{result['decision_id']}: {'identical' if result['identical'] else 'DIFFERENT'} "
        f"({result['rules_compared']} rule decisions compared)"
    )
    text += "".join(f"\n  {json.dumps(d)}" for d in result["differences"])
    _emit(result, args.json, text)
    return EXIT_OK if result["identical"] else EXIT_BLOCKED


def cmd_decision_show(args: argparse.Namespace) -> int:
    r = _load_record(args.record)
    o = r["outcome"]
    lines = [
        f"{r['decision_id']}  {r['created_at']}",
        f"subject: {r['subject']['identity']['id']} @ {(r['subject']['git'] or {}).get('commit', '-')}",
        f"policy {r['engine']['policy_version']} ({r['engine']['registry_digest'][:19]}), {r['engine']['tool']}",
        f"verdict: {o['verdict']} | evidence: {o['evidence_grade']} | "
        f"compliance claim: {'allowed' if o['compliance_claim_allowed'] else 'not allowed'}",
        f"blocking: {', '.join(o['summary']['blocking']) or '-'}",
        f"obligations pending: {', '.join(o['summary'].get('obligations_pending', [])) or '-'}",
    ]
    _emit(r, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_controls_report(args: argparse.Namespace) -> int:
    if args.record:
        controls = _load_record(args.record)["controls"]
    else:
        controls = _session(args).validate_repository(run_external=False)["controls"]
    rows = [c for c in controls["controls"] if not args.framework or c["control"].startswith(args.framework + ":")]
    lines = []
    for c in rows:
        parts = [f"{r['rule_id']}={r['status']}" for r in c["rules"]]
        parts += [f"{o['obligation']}={o['status']}" for o in c["obligations"]]
        lines.append(f"{c['control']:<28} {c['status']:<26} {', '.join(parts)}")
    _emit({"frameworks": controls["frameworks"], "controls": rows}, args.json, "\n".join(lines))
    return EXIT_BLOCKED if any(c["status"] == "failed" for c in rows) else EXIT_OK


def cmd_design_check(args: argparse.Namespace) -> int:
    session = _session(args)
    reg = session.registry
    design = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
    ctx = session.context(task=args.task or design, environment=args.environment)
    result = validate_design(reg, ctx, design)
    lines = []
    for c in result["checks"]:
        lines.append(f"{c['rule_id']:<9} {c['level']:<6} {c['status']:<20} {c['title']}")
        lines += [f"    ! {v['message']} ({v['excerpt']!r})" for v in c["violations"]]
        lines += [f"    ? {q['question']}" for q in c["questions"] if not q["addressed"]]
    lines += ["", f"verdict: {result['verdict']} (heuristic)"]
    _emit(result, args.json, "\n".join(lines))
    return EXIT_BLOCKED if result["verdict"] == "rework_required" else EXIT_OK


SERVER_COMMAND = ["gov", "mcp"]


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path or ".").resolve()
    existing = load_project(root)
    identity = resolve_identity(root, existing.project)
    reg = select_registry(args.registry, existing, identity)
    ctx = resolve_context(reg, root, environment=args.environment, config=existing, identity=identity)
    config = ProjectConfig(
        root=root,
        project=args.project or existing.project,
        policy_version=reg.policy_version,
        registry=existing.registry,
        profiles=args.profile or existing.profiles or ctx.profiles,
        environment=args.environment or existing.environment or ctx.environment,
        overrides=existing.overrides,
        exclude_paths=existing.exclude_paths,
    )
    print(f"{'updated' if existing.exists else 'created'}: {write_project(config).name}")
    block = bootstrap.render_block(reg.policy_version, config.profiles)
    agents = set(args.agents.split(","))
    if "codex" in agents or "agents" in agents:
        print(f"{bootstrap.upsert_block(root / 'AGENTS.md', block)}: AGENTS.md")
    if "claude" in agents:
        print(f"{bootstrap.upsert_block(root / 'CLAUDE.md', block)}: CLAUDE.md")
        print(f"{bootstrap.upsert_mcp_json(root, SERVER_COMMAND)}: .mcp.json")
    if args.ci == "github":
        wf = root / ".github" / "workflows" / "governance.yml"
        wf.parent.mkdir(parents=True, exist_ok=True)
        status = "unchanged" if wf.exists() else "created"
        if not wf.exists():
            wf.write_text(bootstrap.GITHUB_WORKFLOW.format(package=args.package), encoding="utf-8")
        print(f"{status}: {wf.relative_to(root)}")
    if "codex" in agents:
        print("\nCodex reads MCP servers from ~/.codex/config.toml. Add:\n")
        print(bootstrap.codex_snippet(SERVER_COMMAND))
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    root = find_project_root(args.path or ".")
    checks: list[tuple[str, str, str]] = []

    def check(status: str, name: str, detail: str = "") -> None:
        checks.append((status, name, detail))

    config = load_project(root)
    check("ok" if config.exists else "fail", ".governance.yaml", "" if config.exists else "run `gov init`")
    identity = resolve_identity(root, config.project)
    check(
        "ok" if identity.verified else "warn",
        "identity",
        f"{identity.id} ({identity.source}){'' if identity.verified else '; evidence will be advisory'}",
    )
    try:
        reg = select_registry(args.registry, config, identity)
        check(
            "ok",
            "registry",
            f"{reg.root} (policy {reg.policy_version}, {len(reg.rules)} rules, source: {reg.source})",
        )
        check(
            "ok" if reg.verified_by else "warn",
            "registry signature",
            f"verified by key {reg.verified_by}"
            if reg.verified_by
            else f"not verified; set {TRUSTED_KEYS_ENV} and use a signed bundle for authoritative evidence",
        )
        try:
            ctx = resolve_context(reg, root, config=config, identity=identity)
            info = ctx.catalog_info
            check(
                "ok" if info["entry"] else "warn",
                "catalog entry",
                f"{info['entry']} from {info['source']}"
                f"{' (signed by ' + info['verified_by'] + ')' if info['verified_by'] else ''}"
                if info["entry"]
                else "none; attributes default to the strictest values",
            )
            defaults = [d for d, a in ctx.service.attributes.items() if a.trust == "default-strict"]
            if defaults:
                check("warn", "service attributes", f"strict defaults for: {', '.join(defaults)}")
        except RegistryError as exc:
            check("fail", "catalog", str(exc))
    except RegistryError as exc:
        check("fail", "registry", str(exc))
        reg = None
    if reg:
        issues = [i for i in lint_registry(reg) if i["level"] != "info"]
        errors = [i for i in issues if i["level"] == "error"]
        check(
            "fail" if errors else "warn" if issues else "ok",
            "registry lint",
            f"{len(errors)} error(s), {len(issues) - len(errors)} warning(s)",
        )
        if config.policy_version and config.policy_version != reg.policy_version:
            check(
                "warn",
                "policy version",
                f"project pins {config.policy_version}, registry serves "
                f"{reg.policy_version}; run `gov init` after reviewing the changelog",
            )
        elif config.policy_version:
            check("ok", "policy version", config.policy_version)
        for name in ("AGENTS.md", "CLAUDE.md"):
            v = bootstrap.block_version(root / name)
            if v is None:
                check("warn", name, "no governance block; run `gov init`")
            elif v != reg.policy_version:
                check("warn", name, f"block is for policy {v}; run `gov init`")
            else:
                check("ok", name)
        tools = sorted(
            {r.validation.tool for r in reg.rules.values() if r.validation.type == "external"}
            | ({"semgrep"} if any(r.validation.type == "semgrep" for r in reg.rules.values()) else set())
        )
        for tool in tools:
            check(
                "ok" if shutil.which(tool) else "warn",
                f"validator: {tool}",
                shutil.which(tool) or "not installed; rules using it report `error` (blocking with --fail-closed)",
            )
    mcp_json = root / ".mcp.json"
    if mcp_json.exists() and bootstrap.SERVER_NAME in json.loads(mcp_json.read_text()).get("mcpServers", {}):
        check("ok", ".mcp.json", "Claude Code server entry present")
    else:
        check("warn", ".mcp.json", "no engineering-governance entry; run `gov init --agents claude`")
    check(
        "ok" if shutil.which("gov") else "warn",
        "gov on PATH",
        shutil.which("gov") or "MCP clients launch `gov mcp`; install the CLI on PATH",
    )
    try:
        import mcp  # noqa: F401

        check("ok", "mcp sdk")
    except ImportError as exc:
        check("fail", "mcp sdk", str(exc))

    if args.json:
        _emit([{"status": s, "check": n, "detail": d} for s, n, d in checks], True, "")
    else:
        for s, n, d in checks:
            print(f"[{s:^4}] {n}{'  ' + d if d else ''}")
    return EXIT_BLOCKED if any(s == "fail" for s, _, _ in checks) else EXIT_OK


def cmd_registry_lint(args: argparse.Namespace) -> int:
    reg = load_registry(args.registry)
    issues = lint_registry(reg)
    if args.json:
        _emit(issues, True, "")
    else:
        for i in issues:
            print(f"{i['level']:<7} {i['where']}: {i['message']}")
        print(
            f"{len(reg.rules)} rules, {len(reg.profiles)} profiles, {len(reg.waivers)} waivers, "
            f"{len(issues)} issue(s); digest {reg.digest}"
        )
    return EXIT_BLOCKED if any(i["level"] == "error" for i in issues) else EXIT_OK


def cmd_registry_coverage(args: argparse.Namespace) -> int:
    reg = load_registry(args.registry)
    rows: dict[str, dict[str, int]] = {}
    for r in reg.rules.values():
        row = rows.setdefault(r.enforcement.label, {"automated": 0, "manual": 0})
        row["manual" if r.validation.type == "manual" else "automated"] += 1
    _emit(
        rows,
        args.json,
        "\n".join(f"{k:<6} automated={v['automated']:<3} manual={v['manual']}" for k, v in rows.items()),
    )
    return EXIT_OK


def cmd_bundle_build(args: argparse.Namespace) -> int:
    reg = load_registry(args.registry)
    errors = [i for i in lint_registry(reg) if i["level"] == "error"]
    if errors:
        print(f"refusing to bundle: {len(errors)} lint error(s); run `gov registry lint`", file=sys.stderr)
        return EXIT_BLOCKED
    out = Path(args.output or f"governance-bundle-{reg.policy_version}.json")
    bundle = build_bundle(reg, Path(args.sign_key) if args.sign_key else None)
    out.write_text(json.dumps(bundle, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    signed = f", signed by {bundle['signatures'][0]['key_id']}" if bundle["signatures"] else ", unsigned"
    print(f"wrote {out} (policy {reg.policy_version}, {reg.digest}{signed})")
    return EXIT_OK


def cmd_bundle_keygen(args: argparse.Namespace) -> int:
    private, public = Path(args.out), Path(args.out + ".pub")
    if private.exists() and not args.force:
        print(f"error: {private} exists; pass --force to overwrite", file=sys.stderr)
        return EXIT_USAGE
    kid = generate_keypair(private, public)
    print(f"wrote {private} (private, mode 600) and {public}; key id {kid}")
    print(f"Distribute {public} to verifiers via {TRUSTED_KEYS_ENV}; keep the private key in a secret store.")
    return EXIT_OK


def cmd_catalog_show(args: argparse.Namespace) -> int:
    session = _session(args)
    ctx = session.context(paths=args.file)
    data = {
        "identity": ctx.identity.to_dict(),
        "catalog": ctx.catalog_info,
        "service": ctx.service.to_dict(),
        "target_service": ctx.target_service.to_dict() if args.file else None,
        "components": {c: sc.to_dict() for c, sc in ctx.service_contexts.items() if c != "_repository"},
    }
    lines = [
        f"identity: {ctx.identity.id} ({'verified' if ctx.identity.verified else 'unverified'})",
        f"catalog:  {ctx.catalog_info['entry'] or '(no entry)'} {ctx.catalog_info['source'] or ''}",
        "",
    ]
    for name, sc in ctx.service_contexts.items():
        label = "repository" if name == "_repository" else f"component {name}"
        lines.append(label)
        for dim, attr in sc.attributes.items():
            value = ", ".join(attr.value) if isinstance(attr.value, list) else attr.value
            lines.append(f"  {dim:<20} {value or '-':<40} {attr.trust} ({attr.source})")
    _emit(data, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_catalog_import_backstage(args: argparse.Namespace) -> int:
    raw = json.loads(Path(args.entities).read_text(encoding="utf-8"))
    entities = raw.get("items", raw) if isinstance(raw, dict) else raw
    entries = import_backstage(entities, prefix=args.annotation_prefix, default_host=args.host)
    document = build_catalog_document(
        entries,
        source=f"backstage:{Path(args.entities).name}",
        sign_key=Path(args.sign_key) if args.sign_key else None,
    )
    Path(args.output).write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    signed = f", signed by {document['signatures'][0]['key_id']}" if document["signatures"] else ", unsigned"
    print(f"wrote {args.output}: {len(entries)} repositories from {len(entities)} entities{signed}")
    print(f"Point validators at it with {CATALOG_ENV}={args.output}")
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace) -> int:
    from governance.mcp_server import main as serve

    serve(args.registry, args.repo)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gov", description="Engineering Governance Control Plane")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--registry", help="registry directory or bundle .json (default: GOV_REGISTRY, project config)")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser, *, env: bool = True, json_out: bool = True) -> None:
        sp.add_argument("--path", default=".", help="repository root (default: current directory)")
        if env:
            sp.add_argument("--environment", "--env", choices=["development", "staging", "production"])
        if json_out:
            sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("init", help="add governance config, agent bootstrap and MCP config to a repository")
    sp.add_argument("--path", default=".")
    sp.add_argument("--project")
    sp.add_argument("--profile", action="append", help="governance profile (repeatable; default: detected)")
    sp.add_argument("--environment", choices=["development", "staging", "production"])
    sp.add_argument("--agents", default="claude,codex", help="comma list of: claude, codex")
    sp.add_argument("--ci", choices=["github"], help="also write a CI workflow")
    sp.add_argument("--package", default="engineering-governance", help="pip requirement used in CI")
    sp.set_defaults(func=cmd_init)

    prof = sub.add_parser("profile", help="project profile commands").add_subparsers(dest="sub", required=True)
    sp = prof.add_parser("detect", help="detect stack, profiles and environment")
    common(sp)
    sp.set_defaults(func=cmd_profile_detect)

    rules = sub.add_parser("rules", help="rule commands").add_subparsers(dest="sub", required=True)
    sp = rules.add_parser("list", help="list rules applicable to a task")
    common(sp)
    sp.add_argument("--task", help="task description")
    sp.add_argument("--file", action="append", help="file you plan to change (repeatable)")
    sp.add_argument("--limit", type=int, default=10, help="max MEDIUM/SOFT rules")
    sp.add_argument("--all", action="store_true", help="list every rule in the registry")
    sp.set_defaults(func=cmd_rules_list)
    sp = rules.add_parser("why", help="why a rule applies or does not apply here (reason codes)")
    common(sp)
    sp.add_argument("rule_id")
    sp.add_argument("--task")
    sp.add_argument("--file", action="append")
    sp.set_defaults(func=cmd_rules_why)
    sp = rules.add_parser("explain", help="show a rule")
    common(sp, env=False)
    sp.add_argument("rule_id")
    sp.set_defaults(func=cmd_rules_explain)

    sp = sub.add_parser("validate", help="run validators (same policies as CI)")
    common(sp, json_out=False)
    src = sp.add_mutually_exclusive_group()
    src.add_argument("--base", help="validate changes against a git ref, e.g. origin/main")
    src.add_argument("--changed", action="store_true", help="validate uncommitted changes against HEAD")
    src.add_argument("--diff", help="validate a unified diff file ('-' for stdin)")
    sp.add_argument("--task", help="task description (selects manual-review rules)")
    sp.add_argument(
        "--fail-closed",
        action="store_true",
        help="treat unavailable validators of mandatory rules as blocking",
    )
    sp.add_argument("--strict", action="store_true", help="MEDIUM/SOFT failures also block")
    sp.add_argument("--no-external", action="store_true", help="skip external tools (ruff, pip-audit)")
    sp.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    sp.add_argument("--output", "-o")
    sp.add_argument("--verbose", "-v", action="store_true", help="also show passing rules")
    sp.add_argument("--approved-by", help="comma-separated approvers (users or teams) for obligations")
    sp.add_argument("--enforce-obligations", action="store_true", help="pending mandatory obligations block")
    sp.add_argument("--github-pr", type=int, help="read approvals for this pull request from the GitHub API")
    sp.add_argument("--record", help="write a decision record (JSON) to this path")
    sp.add_argument("--sign-key", help=f"Ed25519 key to sign the decision record (default: ${SIGNING_KEY_ENV})")
    sp.add_argument("--store", help="append-only local directory for decision records")
    sp.add_argument("--s3-bucket", help="S3 bucket with Object Lock for decision records")
    sp.add_argument("--s3-prefix", default="decisions/")
    sp.add_argument("--retention-days", type=int, default=2557, help="Object Lock retention (default: 7 years)")
    sp.add_argument("--lock-mode", choices=["COMPLIANCE", "GOVERNANCE"], default="COMPLIANCE")
    sp.add_argument(
        "--require-authoritative",
        action="store_true",
        help="exit 2 unless identity is verified and the registry signature is valid",
    )
    sp.set_defaults(func=cmd_validate)

    design = sub.add_parser("design", help="design review").add_subparsers(dest="sub", required=True)
    sp = design.add_parser("check", help="heuristic check of a design document")
    common(sp)
    sp.add_argument("file", help="design document ('-' for stdin)")
    sp.add_argument("--task")
    sp.set_defaults(func=cmd_design_check)

    sp = sub.add_parser("doctor", help="check governance setup of a repository")
    common(sp, env=False)
    sp.set_defaults(func=cmd_doctor)

    regp = sub.add_parser("registry", help="registry maintenance").add_subparsers(dest="sub", required=True)
    sp = regp.add_parser("lint", help="validate rule metadata, profiles and waivers")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_registry_lint)
    sp = regp.add_parser("coverage", help="automated vs manual validation per enforcement level")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_registry_coverage)

    bundle = sub.add_parser("bundle", help="pinned policy bundles").add_subparsers(dest="sub", required=True)
    sp = bundle.add_parser("build", help="write a policy bundle, optionally signed")
    sp.add_argument("--output", "-o")
    sp.add_argument("--sign-key", help="Ed25519 private key (PEM) to sign the bundle")
    sp.set_defaults(func=cmd_bundle_build)
    sp = bundle.add_parser("keygen", help="generate an Ed25519 signing key pair")
    sp.add_argument("--out", required=True, help="private key path; the public key is written to <out>.pub")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_bundle_keygen)

    cat = sub.add_parser("catalog", help="service catalog").add_subparsers(dest="sub", required=True)
    sp = cat.add_parser("show", help="resolved service attributes for this repository")
    common(sp, env=False)
    sp.add_argument("--file", action="append", help="show the target context for these files")
    sp.set_defaults(func=cmd_catalog_show)
    sp = cat.add_parser("import-backstage", help="convert Backstage entities to a signed catalog file")
    sp.add_argument("entities", help="JSON from the Backstage catalog API (/api/catalog/entities)")
    sp.add_argument("--output", "-o", required=True)
    sp.add_argument("--sign-key", help="Ed25519 private key (PEM)")
    sp.add_argument("--annotation-prefix", default="governance.io/")
    sp.add_argument("--host", default="github.com", help="host for github.com/project-slug annotations")
    sp.set_defaults(func=cmd_catalog_import_backstage)

    dec = sub.add_parser("decision", help="decision records").add_subparsers(dest="sub", required=True)
    for name, func, text in (
        ("verify", cmd_decision_verify, "check digest, id and signature"),
        ("replay", cmd_decision_replay, "re-run rule resolution on recorded inputs"),
        ("show", cmd_decision_show, "summarise a decision record"),
    ):
        sp = dec.add_parser(name, help=text)
        sp.add_argument("record")
        sp.add_argument("--json", action="store_true")
        sp.set_defaults(func=func)

    ctl = sub.add_parser("controls", help="control coverage").add_subparsers(dest="sub", required=True)
    sp = ctl.add_parser("report", help="status per control (from a decision record or a fresh run)")
    common(sp, env=False)
    sp.add_argument("--record")
    sp.add_argument("--framework", help="e.g. PCI-DSS-4.0")
    sp.set_defaults(func=cmd_controls_report)

    sp = sub.add_parser("mcp", help="run the MCP server over stdio")
    sp.add_argument("--repo", help="repository root (default: current directory)")
    sp.set_defaults(func=cmd_mcp)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
