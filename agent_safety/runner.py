"""Run an experiment described by a YAML file. Writes one JSON trace per trial (resumable)."""
from __future__ import annotations

import json
import platform
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

from .agent import ScriptedPolicy, TrialSpec, run_trial
from .attacks import ALL_STYLES
from .providers import Budget, BudgetExceeded, make_provider
from .safeguards import resolve_configs
from .tasks import ALL_TASKS, TASK_BY_ID, TASKS, variants_for


def load_config(path: str) -> dict:
    cfg = yaml.safe_load(Path(path).read_text())
    cfg.setdefault("name", Path(path).stem)
    cfg.setdefault("seed", 0)
    cfg.setdefault("trials", 1)
    cfg.setdefault("max_steps", 10)
    cfg.setdefault("concurrency", 4)
    cfg.setdefault("cache_dir", ".cache/llm")
    cfg.setdefault("tasks", "all")
    cfg.setdefault("styles", "all")
    cfg.setdefault("include_benign", True)
    cfg.setdefault("include_faults", True)
    cfg.setdefault("configs", ["baseline"])
    cfg.setdefault("ablate", [])
    cfg.setdefault("budget", {})
    return cfg


def agent_label(spec: dict) -> str:
    if spec["provider"] == "scripted":
        return f"scripted:{spec['policy']}"
    return spec.get("name") or f"{spec['provider']}:{spec['model']}"


def build_plan(cfg: dict, *, has_judge: bool) -> tuple[list, list, list[str]]:
    guards = resolve_configs(cfg["configs"], cfg["ablate"])
    notes = []
    if not has_judge:
        skipped = [g.name for g in guards if g.needs_judge]
        if skipped:
            notes.append(f"skipped (no judge model configured): {', '.join(skipped)}")
        guards = [g for g in guards if not g.needs_judge]
    if cfg["tasks"] == "all":
        tasks = [t for t in ALL_TASKS if cfg["include_faults"] or not t.is_fault]
    else:
        tasks = [TASK_BY_ID[t] for t in cfg["tasks"]]
    styles = list(ALL_STYLES) if cfg["styles"] == "all" else list(cfg["styles"])
    specs = []
    for a in cfg["agents"]:
        label = agent_label(a)
        for g in guards:
            for t in tasks:
                for v in variants_for(t, styles, cfg["include_benign"]):
                    for i in range(cfg["trials"]):
                        specs.append(TrialSpec(label, g.name, t.id, v, i))
    return specs, guards, notes


def estimate(cfg: dict, specs: list, guards: list) -> str:
    gmap = {g.name: g for g in guards}
    lines = [f"experiment {cfg['name']}: {len(specs)} trials"]
    for a in cfg["agents"]:
        label = agent_label(a)
        mine = [s for s in specs if s.model == label]
        judged = sum(1 for s in mine if gmap[s.config].needs_judge)
        if a["provider"] == "scripted":
            lines.append(f"  {label:32} {len(mine):6} trials  (offline, free)")
        else:
            lines.append(f"  {label:32} {len(mine):6} trials  ~{len(mine) * 4:,} agent calls, "
                         f"~{judged * 4:,} judge calls (rough: ~4 steps/trial, ~1.5k input tokens/call)")
    lines.append(f"  configs: {', '.join(gmap)}")
    return "\n".join(lines)


def _git_rev() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              timeout=5).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def run(config_path: str, out_dir: str | None = None, *, resume: bool = True, dry_run: bool = False,
        quiet: bool = False) -> Path:
    cfg = load_config(config_path)
    out = Path(out_dir or f"results/{cfg['name']}")
    b = cfg["budget"] or {}
    budget = Budget(b.get("max_usd"), b.get("max_tokens"), {k: tuple(v) for k, v in (b.get("prices") or {}).items()})
    judge = make_provider(cfg["judge"], budget=budget, cache_dir=cfg["cache_dir"]) if cfg.get("judge") else None
    specs, guards, notes = build_plan(cfg, has_judge=judge is not None)
    for n in notes:
        print("note:", n)
    if dry_run:
        print(estimate(cfg, specs, guards))
        return out
    out.mkdir(parents=True, exist_ok=True)
    (out / "config.yaml").write_text(Path(config_path).read_text())
    traces_path = out / "traces.jsonl"
    done = set()
    if resume and traces_path.exists():
        for line in traces_path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                if not r.get("error"):
                    done.add(r["key"])
        # drop errored rows so they are retried
        kept = [ln for ln in traces_path.read_text().splitlines() if ln.strip() and json.loads(ln)["key"] in done]
        traces_path.write_text("".join(k + "\n" for k in kept))
    elif traces_path.exists():
        traces_path.unlink()
    todo = [s for s in specs if s.key not in done]

    policies = {}
    for a in cfg["agents"]:
        label = agent_label(a)
        if a["provider"] == "scripted":
            policies[label] = ScriptedPolicy(naive=a["policy"] == "naive")
        else:
            policies[label] = make_provider(a, budget=budget, cache_dir=cfg["cache_dir"])
    gmap = {g.name: g for g in guards}

    manifest = {"name": cfg["name"], "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "git": _git_rev(),
                "python": sys.version.split()[0], "platform": platform.platform(),
                "agents": [agent_label(a) for a in cfg["agents"]],
                "judge": (cfg["judge"]["provider"] + ":" + cfg["judge"]["model"]) if cfg.get("judge") else None,
                "configs": {g.name: g.layer_names for g in guards}, "trials_planned": len(specs),
                "trials_resumed": len(done), "notes": notes,
                "scripted_only": all(a["provider"] == "scripted" for a in cfg["agents"])}
    lock = threading.Lock()
    n_done = [0]
    t_start = time.time()

    def work(spec):
        return run_trial(spec, TASK_BY_ID[spec.task], gmap[spec.config], policies[spec.model], judge=judge,
                         max_steps=cfg["max_steps"], seed=cfg["seed"])

    stopped = None
    with open(traces_path, "a") as fh, ThreadPoolExecutor(max_workers=max(1, cfg["concurrency"])) as pool:
        futs = {pool.submit(work, s): s for s in todo}
        try:
            for f in as_completed(futs):
                tr = f.result()
                with lock:
                    fh.write(json.dumps(tr, default=str) + "\n")
                    fh.flush()
                    n_done[0] += 1
                    if not quiet and (n_done[0] % max(1, len(todo) // 10) == 0 or n_done[0] == len(todo)):
                        print(f"  {n_done[0]}/{len(todo)} trials  ({time.time() - t_start:.0f}s)  "
                              f"budget={budget.snapshot()}", flush=True)
        except BudgetExceeded as e:
            stopped = str(e)
            print("STOPPED:", e)
            for f in futs:
                f.cancel()
    manifest.update({"finished": time.strftime("%Y-%m-%dT%H:%M:%S"), "usage": budget.snapshot(),
                     "stopped_early": stopped})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return out


def list_tasks() -> str:
    rows = [f"{'task':26} {'category':10} {'variants':>8}  scopes / attack goal"]
    for t in ALL_TASKS:
        v = variants_for(t)
        rows.append(f"{t.id:26} {t.category:10} {len(v):>8}  {', '.join(t.scopes)}"
                    + (f"  -> {t.goal}" if t.goal else "  (seeded fault)"))
    n_attack = sum(len(t.styles()) for t in TASKS)
    rows.append(f"\n{len(TASKS)} benign tasks x attack styles = {n_attack} attack variants, "
                f"{len(ALL_TASKS) - len(TASKS)} seeded-fault tasks")
    return "\n".join(rows)
