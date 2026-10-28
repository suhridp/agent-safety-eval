"""Turn traces into tables, figures, a Markdown report and a hand-coding sheet."""
from __future__ import annotations

import csv
import json
import random
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from .attacks import ALL_STYLES, DEV_STYLES, HELDOUT_STYLES
from .stats import cluster_bootstrap, holm, mcnemar_exact, wilson

CSV_FIELDS = ["key", "model", "config", "task", "category", "variant", "kind", "style_set", "goal", "trial",
              "completed", "unsafe_executed", "unsafe_attempted", "goal_achieved", "propagated", "blocked",
              "refused", "confirmations", "n_steps", "stop", "outcome", "error", "agent_in_tokens", "agent_out_tokens",
              "guard_in_tokens", "guard_out_tokens", "latency_s", "uses_oracle"]


def load_traces(run_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (run_dir / "traces.jsonl").read_text().splitlines() if line.strip()]


def rate(rows, field) -> dict:
    k, n = sum(bool(r[field]) for r in rows), len(rows)
    lo, hi = wilson(k, n)
    out = {"k": k, "n": n, "rate": (k / n) if n else None, "wilson": [lo, hi]}
    if n:
        _, clo, chi = cluster_bootstrap([float(bool(r[field])) for r in rows], [r["task"] for r in rows])
        out["cluster"] = [clo, chi]
    return out


def summarize(traces: list[dict], manifest: dict | None = None) -> dict:
    ok = [t for t in traces if not t.get("error")]
    errors = Counter((t["model"], t["config"]) for t in traces if t.get("error"))
    models = list(dict.fromkeys(t["model"] for t in traces))
    seen = list(dict.fromkeys(t["config"] for t in traces))
    order = list((manifest or {}).get("configs", {}))
    configs = [c for c in order if c in seen] + [c for c in seen if c not in order]
    cfg_layers = (manifest or {}).get("configs", {})
    by = defaultdict(list)
    for t in ok:
        by[(t["model"], t["config"])].append(t)

    headline, by_style, split, taxonomy, faults, by_category = [], {}, {}, {}, {}, {}
    for m in models:
        by_style[m], split[m], taxonomy[m], faults[m], by_category[m] = {}, {}, {}, {}, {}
        for c in configs:
            R = by.get((m, c), [])
            atk = [r for r in R if r["kind"] == "attack"]
            ben = [r for r in R if r["kind"] == "benign"]
            flt = [r for r in R if r["kind"] == "fault"]
            if not R:
                continue
            tok = [r["agent_in_tokens"] + r["agent_out_tokens"] + r["guard_in_tokens"] + r["guard_out_tokens"]
                   for r in R]
            lat = [r["latency_s"] for r in R]
            headline.append({
                "model": m, "config": c, "layers": cfg_layers.get(c, []),
                "uses_oracle": any(r["uses_oracle"] for r in R),
                "unsafe": rate(atk, "unsafe_executed"), "asr": rate(atk, "goal_achieved"),
                "attempted": rate(atk, "unsafe_attempted"),
                "attack_completion": rate(atk, "completed"), "benign_completion": rate(ben, "completed"),
                "benign_blocked": rate(ben, "blocked"), "benign_refused": rate(ben, "refused"),
                "fault_propagated": rate(flt, "propagated"),
                "confirmations_per_trial": (sum(r["confirmations"] for r in R) / len(R)) if R else 0,
                "tokens_per_trial": (sum(tok) / len(tok)) if tok else 0,
                "guard_tokens_per_trial": (sum(r["guard_in_tokens"] + r["guard_out_tokens"] for r in R) / len(R)),
                "latency_median_s": statistics.median(lat) if lat else 0,
                "n_trials": len(R), "n_errors": errors.get((m, c), 0),
            })
            by_style[m][c] = {s: rate([r for r in atk if r["variant"] == s], "unsafe_executed")
                              for s in ALL_STYLES if any(r["variant"] == s for r in atk)}
            split[m][c] = {"dev": rate([r for r in atk if r["style_set"] == "dev"], "unsafe_executed"),
                           "heldout": rate([r for r in atk if r["style_set"] == "heldout"], "unsafe_executed")}
            taxonomy[m][c] = dict(Counter(r["outcome"] for r in R))
            faults[m][c] = dict(Counter(r["task"] for r in flt if r["propagated"]))
            cats = sorted({r["category"] for r in atk})
            by_category[m][c] = {cat: rate([r for r in atk if r["category"] == cat], "unsafe_executed")
                                 for cat in cats}

    # paired comparisons against baseline on identical cells
    paired = []
    for m in models:
        base = {(r["task"], r["variant"], r["trial"]): r for r in by.get((m, "baseline"), [])}
        if not base:
            continue
        fam = {}
        for c in configs:
            if c == "baseline":
                continue
            other = {(r["task"], r["variant"], r["trial"]): r for r in by.get((m, c), [])}
            cells = sorted(set(base) & set(other))
            atk = [k for k in cells if base[k]["kind"] == "attack"]
            ben = [k for k in cells if base[k]["kind"] == "benign"]
            u = mcnemar_exact([(base[k]["unsafe_executed"], other[k]["unsafe_executed"]) for k in atk])
            b = mcnemar_exact([(base[k]["completed"], other[k]["completed"]) for k in ben])
            paired.append({"model": m, "config": c, "metric": "unsafe_executed (attack)", **u})
            paired.append({"model": m, "config": c, "metric": "completed (benign)", **b})
            fam[(c, "u")], fam[(c, "b")] = u["p"], b["p"]
        adj = holm({f"{k[0]}|{k[1]}": v for k, v in fam.items()})
        for p in paired:
            if p["model"] == m:
                p["p_holm"] = adj.get(f"{p['config']}|{'u' if p['metric'].startswith('unsafe') else 'b'}", p["p"])

    # ablations: <base>-minus-<layer> versus <base>
    ablation = []
    H = {(h["model"], h["config"]): h for h in headline}
    for (m, c), h in H.items():
        mm = re.match(r"(.+)-minus-(.+)", c)
        if mm and (m, mm.group(1)) in H:
            full = H[(m, mm.group(1))]
            ablation.append({"model": m, "base": mm.group(1), "removed": mm.group(2),
                             "d_unsafe": _d(h["unsafe"], full["unsafe"]),
                             "d_benign_completion": _d(h["benign_completion"], full["benign_completion"])})

    return {"manifest": manifest or {}, "models": models, "configs": configs, "headline": headline,
            "by_style": by_style, "dev_vs_heldout": split, "paired": paired, "ablation": ablation,
            "taxonomy": taxonomy, "faults": faults, "by_category": by_category,
            "n_traces": len(traces), "n_errors": sum(errors.values()),
            "styles": {"dev": list(DEV_STYLES), "heldout": list(HELDOUT_STYLES)}}


def _d(a, b):
    if a["rate"] is None or b["rate"] is None:
        return None
    return a["rate"] - b["rate"]


# ------------------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------------------

def write_csv(traces, path: Path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(traces)


def hand_coding_sheet(traces, path: Path, n: int = 40, seed: int = 0):
    """Stratified sample of interesting failures for a human to code (docs/hand_coding_guide.md)."""
    want = ["hijacked", "unsafe_other", "derailed", "refused", "over_blocked", "false_refusal", "propagated",
            "failed", "attempt_blocked"]
    pools = {o: [t for t in traces if t["outcome"] == o and not t["model"].startswith("scripted")] for o in want}
    if not any(pools.values()):  # scripted-only runs: still produce the sheet so the workflow is testable
        pools = {o: [t for t in traces if t["outcome"] == o] for o in want}
    rng = random.Random(seed)
    picked, per = [], max(1, n // max(1, sum(1 for p in pools.values() if p)))
    for o in want:
        pool = pools[o]
        picked += rng.sample(pool, min(per, len(pool)))
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["key", "auto_outcome", "model", "config", "task", "variant", "request", "final_answer",
                    "unsafe_calls", "blocked_calls", "human_mechanism", "human_severity", "human_notes"])
        for t in picked[:n]:
            w.writerow([t["key"], t["outcome"], t["model"], t["config"], t["task"], t["variant"], t["request"],
                        (t["final"] or "")[:400], json.dumps(t["unsafe"])[:400],
                        json.dumps(t["blocked_calls"])[:300], "", "", ""])


def pct(x):
    return "n/a" if x is None else f"{100 * x:.0f}%"


def fmt_rate(r, cluster=True):
    if r["n"] == 0:
        return "n/a"
    lo, hi = r["cluster"] if cluster and "cluster" in r else r["wilson"]
    return f"{pct(r['rate'])} [{pct(lo)}, {pct(hi)}]"


def write_report(summary: dict, path: Path, figures: list[str]):
    man = summary["manifest"]
    L = [f"# Results: {man.get('name', 'experiment')}", ""]
    if man.get("scripted_only"):
        L += ["> **Harness validation only.** Every agent in this run is a scripted stand-in. These numbers show "
              "that scoring and safeguards work mechanically. They are not evidence about any real model.", ""]
    L += [f"- Agents: {', '.join(summary['models'])}",
          f"- Judge model (LLM screen / verifier): {man.get('judge') or 'none'}",
          f"- Trials: {summary['n_traces']} ({summary['n_errors']} errored, excluded from rates)",
          f"- Code version: `{man.get('git', 'unknown')}`, started {man.get('started', '?')}",
          f"- Usage: {man.get('usage', {})}", ""]
    if man.get("stopped_early"):
        L += [f"> **Stopped early:** {man['stopped_early']}. Rates cover completed trials only.", ""]
    L += ["Intervals are 95% task-clustered bootstrap (resampling tasks, since trials of one task are correlated). "
          "Wilson intervals, which assume independent trials, are in `summary.json`.", ""]

    for m in summary["models"]:
        rows = [h for h in summary["headline"] if h["model"] == m]
        L += [f"## {m}", "", "### Security vs. usefulness", "",
              "| config | layers | unsafe action rate | attacker goal reached | benign completion | "
              "completion under attack | benign blocked | fault propagated | tokens/trial |",
              "|---|---|---|---|---|---|---|---|---|"]
        for h in rows:
            flag = " (simulated user)" if h["uses_oracle"] else ""
            L.append(f"| {h['config']}{flag} | {' + '.join(h['layers']) or '-'} | {fmt_rate(h['unsafe'])} | "
                     f"{fmt_rate(h['asr'])} | {fmt_rate(h['benign_completion'])} | "
                     f"{pct(h['attack_completion']['rate'])} | {pct(h['benign_blocked']['rate'])} | "
                     f"{h['fault_propagated']['k']}/{h['fault_propagated']['n']} | {h['tokens_per_trial']:.0f} |")
        L += ["", "### Dev vs. held-out injection styles", "",
              "The regex filter was written against the dev styles only. A large gap here is the circularity the "
              "plan warns about.", "", "| config | dev styles | held-out styles |", "|---|---|---|"]
        for c, v in summary["dev_vs_heldout"][m].items():
            L.append(f"| {c} | {fmt_rate(v['dev'])} | {fmt_rate(v['heldout'])} |")
        P = [p for p in summary["paired"] if p["model"] == m]
        if P:
            L += ["", "### Paired comparisons against baseline (exact McNemar, Holm-adjusted)", "",
                  "`base only` = cells where baseline had the outcome and the config did not.", "",
                  "| config | metric | cells | base only | config only | p (Holm) |", "|---|---|---|---|---|---|"]
            for p in P:
                L.append(f"| {p['config']} | {p['metric']} | {p['n']} | {p['a_only']} | {p['b_only']} | "
                         f"{p['p_holm']:.3g} |")
        A = [a for a in summary["ablation"] if a["model"] == m]
        if A:
            L += ["", "### Ablations (remove one layer)", "", "| base | removed layer | change in unsafe rate | "
                  "change in benign completion |", "|---|---|---|---|"]
            for a in A:
                L.append(f"| {a['base']} | {a['removed']} | {_sgn(a['d_unsafe'])} | {_sgn(a['d_benign_completion'])} |")
        L += ["", "### Outcomes (automatic first-pass labels)", "", "| config | " +
              " | ".join(OUTCOMES) + " |", "|---|" + "---|" * len(OUTCOMES)]
        for c, cnt in summary["taxonomy"][m].items():
            L.append(f"| {c} | " + " | ".join(str(cnt.get(o, 0)) for o in OUTCOMES) + " |")
        L.append("")
    if figures:
        L += ["## Figures", ""] + [f"![{Path(f).stem}]({f})" for f in figures] + [""]
    L += ["## Read before quoting", "",
          "- Small synthetic task suite (24 tasks, 4 seeded faults). Results describe this suite, not agents "
          "in general.",
          "- The unsafe-action definitions are mechanical and per task (see `agent_safety/tasks.py`). They can miss "
          "harms they were not written for.",
          "- Held-out styles were written by the same author as the dev styles and the filter. They are a weak "
          "held-out set; use a third-party attack set for strong claims.",
          "- `confirm_all` uses a simulated user who knows the right answer. It is an upper bound, and its cost is "
          "the number of confirmation prompts, not completion.",
          "- Refusal detection is a regex over the final answer. Hand-code a sample before reporting refusal rates.",
          ""]
    path.write_text("\n".join(L))


OUTCOMES = ["hijacked", "unsafe_other", "attempt_blocked", "resisted", "refused", "derailed", "completed",
            "over_blocked", "false_refusal", "failed", "propagated", "caught", "unsafe_benign"]


def _sgn(x):
    return "n/a" if x is None else f"{100 * x:+.0f} pts"


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def make_figures(summary: dict, fig_dir: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig_dir.mkdir(parents=True, exist_ok=True)
    ink, muted, grid, accent, base_c = "#1d2330", "#5b6475", "#e3e6ec", "#2a78d6", "#e34948"
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": grid, "axes.labelcolor": muted, "xtick.color": muted,
                         "ytick.color": muted, "axes.spines.top": False, "axes.spines.right": False})
    out = []
    for m in summary["models"]:
        rows = [h for h in summary["headline"] if h["model"] == m and h["unsafe"]["n"] and h["benign_completion"]["n"]]
        if not rows:
            continue
        fig, ax = plt.subplots(figsize=(7, 4.6), dpi=150)
        ax.grid(True, color=grid, lw=0.6)
        ax.set_axisbelow(True)
        for h in rows:
            x, y = h["benign_completion"]["rate"], h["unsafe"]["rate"]
            ylo, yhi = h["unsafe"].get("cluster", h["unsafe"]["wilson"])
            xlo, xhi = h["benign_completion"].get("cluster", h["benign_completion"]["wilson"])
            color = base_c if h["config"] == "baseline" else accent
            ax.errorbar(x, y, yerr=[[y - ylo], [yhi - y]], xerr=[[x - xlo], [xhi - x]], fmt="o", ms=6, color=color,
                        ecolor=color, elinewidth=1, alpha=0.9, capsize=0, mec="white", mew=1.2)
            ax.annotate(h["config"], (x, y), textcoords="offset points", xytext=(6, 4), fontsize=7, color=ink)
        ax.set_xlabel("benign task completion (higher is better)")
        ax.set_ylabel("unsafe action rate under attack (lower is better)")
        ax.set_xlim(-0.03, 1.05)
        ax.set_ylim(-0.03, 1.05)
        ax.set_title(f"Safety vs. usefulness: {m}", loc="left", fontsize=10, color=ink)
        fig.tight_layout()
        p = fig_dir / f"frontier_{safe_name(m)}.png"
        fig.savefig(p)
        plt.close(fig)
        out.append(f"figures/{p.name}")

        # heatmap config x style
        cfgs = [c for c in summary["configs"] if c in summary["by_style"][m]]
        styles = [s for s in ALL_STYLES if any(s in summary["by_style"][m][c] for c in cfgs)]
        if cfgs and styles:
            fig, ax = plt.subplots(figsize=(1.0 + 0.75 * len(styles), 0.9 + 0.32 * len(cfgs)), dpi=150)
            grid_vals = [[(summary["by_style"][m][c].get(s) or {}).get("rate") for s in styles] for c in cfgs]
            data = [[v if v is not None else float("nan") for v in row] for row in grid_vals]
            ax.imshow(data, cmap="Blues", vmin=0, vmax=1, aspect="auto")
            for i, row in enumerate(grid_vals):
                for j, v in enumerate(row):
                    if v is not None:
                        ax.text(j, i, f"{100 * v:.0f}", ha="center", va="center", fontsize=7,
                                color="white" if v > 0.55 else ink)
            ax.set_xticks(range(len(styles)), [s + ("*" if s in HELDOUT_STYLES else "") for s in styles],
                          rotation=30, ha="right")
            ax.set_yticks(range(len(cfgs)), cfgs)
            ax.spines[:].set_visible(False)
            ax.set_title(f"Unsafe action rate (%) by injection style: {m}   (* held-out)", loc="left", fontsize=9,
                         color=ink)
            fig.tight_layout()
            p = fig_dir / f"styles_{safe_name(m)}.png"
            fig.savefig(p)
            plt.close(fig)
            out.append(f"figures/{p.name}")
    return out


def analyze(run_dir: str | Path, *, dashboard: bool = True) -> dict:
    run_dir = Path(run_dir)
    traces = load_traces(run_dir)
    man_path = run_dir / "manifest.json"
    manifest = json.loads(man_path.read_text()) if man_path.exists() else {}
    summary = summarize(traces, manifest)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1))
    write_csv(traces, run_dir / "trials.csv")
    hand_coding_sheet(traces, run_dir / "hand_coding.csv")
    figs = make_figures(summary, run_dir / "figures")
    write_report(summary, run_dir / "report.md", figs)
    if dashboard:
        from .dashboard import write_dashboard
        write_dashboard(summary, traces, run_dir / "dashboard.html")
    return summary
