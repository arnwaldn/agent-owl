"""
ATUM Audit Agent CLI.
Usage:
    atum-audit start [--config PATH]       Start daemon (watchdog + periodic scan)
    atum-audit scan [--config PATH]        One-shot full scan
    atum-audit verify <filepath>           Verify single file integrity
    atum-audit history <filepath>          Show audit trail for a file
    atum-audit violations                  List all integrity violations
    atum-audit stats                       Show store statistics
    atum-audit query "<SPARQL>"            Run arbitrary SPARQL query
    atum-audit init [--path DIR]           Initialize config + store in directory

    atum-audit compliance status <system>  Show compliance status for an AI system
    atum-audit compliance report <system>  Full compliance report (Art. 17)
    atum-audit compliance incidents [--system NAME]  List incidents (Art. 62)
    atum-audit compliance retention        Check log retention compliance (Art. 12)
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

from .agent import AuditAgent


def cmd_start(args):
    agent = AuditAgent(args.config)
    agent.start()


def cmd_scan(args):
    agent = AuditAgent(args.config)
    agent.full_scan()
    agent.flush()
    print(json.dumps(agent.stats(), indent=2))


def cmd_verify(args):
    agent = AuditAgent(args.config)
    result = agent.verify_file(args.filepath)
    print(json.dumps(result, indent=2))
    if result.get("status") == "VIOLATION":
        sys.exit(1)


def cmd_history(args):
    agent = AuditAgent(args.config)
    history = agent.history(args.filepath)
    if not history:
        print("No audit trail found for this file.")
        return
    for entry in history:
        print(json.dumps(entry, indent=2))


def cmd_violations(args):
    agent = AuditAgent(args.config)
    viols = agent.violations()
    if not viols:
        print("No integrity violations detected.")
        return
    for v in viols:
        print(json.dumps(v, indent=2))
    sys.exit(1 if viols else 0)


def cmd_stats(args):
    agent = AuditAgent(args.config)
    print(json.dumps(agent.stats(), indent=2))


def cmd_query(args):
    agent = AuditAgent(args.config)
    results = agent.query(args.sparql)
    print(json.dumps(results, indent=2, default=str))


def cmd_compliance(args):
    """Dispatch compliance subcommands."""
    agent = AuditAgent(args.config)
    cm = agent.compliance

    if args.compliance_command == "status":
        result = cm.store.get_compliance_status(args.system)
        if result is None:
            print(f"AI system '{args.system}' not found.", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(result, indent=2, default=str))

    elif args.compliance_command == "report":
        report = cm.compliance_report(args.system)
        if "error" in report:
            print(report["error"], file=sys.stderr)
            sys.exit(1)
        print(json.dumps(report, indent=2, default=str))

    elif args.compliance_command == "incidents":
        incidents = cm.store.get_incidents(
            system_name=getattr(args, "system", None),
        )
        if not incidents:
            print("No incidents found.", file=sys.stderr)
            return
        for inc in incidents:
            print(json.dumps(inc, indent=2, default=str))

    elif args.compliance_command == "retention":
        result = cm.check_retention_compliance()
        print(json.dumps(result, indent=2, default=str))
        if not result["all_ok"]:
            sys.exit(1)

    elif args.compliance_command == "validate":
        try:
            report = cm.validate_system(args.system)
        except ImportError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        print(f"Conforms: {report.conforms}")
        print(f"Errors: {report.stats['errors']}, Warnings: {report.stats['warnings']}")
        for v in report.violations:
            print(f"  [{v.severity}] {v.path}: {v.message}")
        if not report.conforms:
            sys.exit(1)

    elif args.compliance_command == "annex-iv":
        report = cm.annex_iv_status(args.system)
        print(f"Annex IV completeness: {report.completeness_pct}%")
        for pt in report.points:
            status = "OK" if pt.complete else f"MISSING: {', '.join(pt.missing)}"
            print(f"  [{pt.pct:.0f}%] {pt.label} — {status}")
        if report.missing_fields:
            sys.exit(1)

    elif args.compliance_command == "export":
        output = cm.export_report(
            args.system,
            fmt=args.format,
            include_validation=not args.no_validation,
            include_annex_iv=not args.no_annex_iv,
        )
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(output)


def cmd_init(args):
    from .discovery import auto_init_project

    target = Path(args.path).resolve()
    lib_dir = Path(__file__).parent.parent
    config_path = auto_init_project(target, lib_dir=lib_dir)
    print(f"Initialized in {target}")
    print(f"Config: {config_path}")
    print(f"Run: atum-audit start --config {config_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="atum-audit",
        description="ATUM Cryptographic Audit Agent — OWL-backed file integrity monitoring",
    )
    parser.add_argument("--config", default="atum-audit.config.json", help="Config file path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("start", help="Start audit daemon")
    sub.add_parser("scan", help="One-shot full scan")

    p_verify = sub.add_parser("verify", help="Verify single file")
    p_verify.add_argument("filepath")

    p_hist = sub.add_parser("history", help="File audit trail")
    p_hist.add_argument("filepath")

    sub.add_parser("violations", help="List integrity violations")
    sub.add_parser("stats", help="Store statistics")

    p_query = sub.add_parser("query", help="SPARQL query")
    p_query.add_argument("sparql")

    p_init = sub.add_parser("init", help="Initialize audit in directory")
    p_init.add_argument("--path", default=".", help="Target directory")

    # Compliance subcommands (EU AI Act)
    p_comp = sub.add_parser("compliance", help="EU AI Act compliance (Reg. 2024/1689)")
    comp_sub = p_comp.add_subparsers(dest="compliance_command", required=True)

    p_comp_status = comp_sub.add_parser("status", help="Compliance status for an AI system")
    p_comp_status.add_argument("system", help="AI system name")

    p_comp_report = comp_sub.add_parser("report", help="Full compliance report (Art. 17)")
    p_comp_report.add_argument("system", help="AI system name")

    p_comp_incidents = comp_sub.add_parser("incidents", help="List incidents (Art. 62)")
    p_comp_incidents.add_argument("--system", default=None, help="Filter by AI system name")

    comp_sub.add_parser("retention", help="Check log retention compliance (Art. 12)")

    p_comp_validate = comp_sub.add_parser("validate", help="SHACL validation of an AI system")
    p_comp_validate.add_argument("system", help="AI system name")

    p_comp_annex = comp_sub.add_parser("annex-iv", help="Annex IV documentation completeness")
    p_comp_annex.add_argument("system", help="AI system name")

    p_comp_export = comp_sub.add_parser("export", help="Export compliance report (HTML/MD)")
    p_comp_export.add_argument("system", help="AI system name")
    p_comp_export.add_argument(
        "--format", choices=["html", "md"], default="html", help="Output format",
    )
    p_comp_export.add_argument("--output", default=None, help="Output file path")
    p_comp_export.add_argument("--no-validation", action="store_true", help="Skip SHACL validation")
    p_comp_export.add_argument("--no-annex-iv", action="store_true", help="Skip Annex IV check")

    args = parser.parse_args()

    dispatch = {
        "start": cmd_start,
        "scan": cmd_scan,
        "verify": cmd_verify,
        "history": cmd_history,
        "violations": cmd_violations,
        "stats": cmd_stats,
        "query": cmd_query,
        "init": cmd_init,
        "compliance": cmd_compliance,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
