"""Command line.

  python -m agent_safety tasks                         # show the task suite
  python -m agent_safety run configs/smoke.yaml        # run + analyse (resumes by default)
  python -m agent_safety run configs/main.yaml --dry-run
  python -m agent_safety analyze results/smoke         # rebuild report/figures/dashboard from traces
"""
from __future__ import annotations

import argparse
import sys

from .analysis import analyze
from .runner import list_tasks, run


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m agent_safety")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run an experiment from a YAML config, then analyse it")
    r.add_argument("config")
    r.add_argument("--out", default=None, help="output directory (default results/<name>)")
    r.add_argument("--fresh", action="store_true", help="discard existing traces instead of resuming")
    r.add_argument("--dry-run", action="store_true", help="print the trial count and rough call estimate only")
    r.add_argument("--no-dashboard", action="store_true")
    a = sub.add_parser("analyze", help="rebuild summary, report, figures and dashboard from traces")
    a.add_argument("run_dir")
    a.add_argument("--no-dashboard", action="store_true")
    sub.add_parser("tasks", help="list the task suite")
    args = ap.parse_args(argv)

    if args.cmd == "tasks":
        print(list_tasks())
        return 0
    if args.cmd == "run":
        out = run(args.config, args.out, resume=not args.fresh, dry_run=args.dry_run)
        if args.dry_run:
            return 0
        summary = analyze(out, dashboard=not args.no_dashboard)
        print(headline_text(summary))
        print(f"\nwrote {out}/report.md, summary.json, trials.csv, traces.jsonl"
              + ("" if args.no_dashboard else ", dashboard.html"))
        return 0
    if args.cmd == "analyze":
        summary = analyze(args.run_dir, dashboard=not args.no_dashboard)
        print(headline_text(summary))
        return 0
    return 1


def headline_text(summary) -> str:
    pc = lambda x: "  n/a" if x is None else f"{100 * x:4.0f}%"  # noqa: E731
    lines = []
    if summary["manifest"].get("scripted_only"):
        lines.append("HARNESS VALIDATION ONLY: scripted stand-in agents, not model evidence.")
    for m in summary["models"]:
        lines.append(f"\n{m}")
        lines.append(f"  {'config':28}{'unsafe [task-clustered 95% CI]':32}{'goal':>6}"
                     f"{'benign done':>13}{'blocked':>9}")
        for h in summary["headline"]:
            if h["model"] != m:
                continue
            u = h["unsafe"]
            ci = u.get("cluster", u["wilson"])
            lines.append(f"  {h['config']:28}{pc(u['rate'])} [{pc(ci[0])},{pc(ci[1])}]{'':13}"
                         f"{pc(h['asr']['rate']):>6}{pc(h['benign_completion']['rate']):>13}"
                         f"{pc(h['benign_blocked']['rate']):>9}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
