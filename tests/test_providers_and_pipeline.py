"""Real provider code against a local mock server, then the whole pipeline end to end."""
import json
import os

import pytest
import yaml

from agent_safety.agent import TrialSpec, run_trial
from agent_safety.analysis import analyze
from agent_safety.providers import (AnthropicProvider, Budget, BudgetExceeded, OpenAICompatProvider)
from agent_safety.runner import run
from agent_safety.safeguards import Safeguards
from agent_safety.tasks import TASK_BY_ID
from mock_llm import MockLLMServer


@pytest.fixture
def server():
    with MockLLMServer() as s:
        yield s


@pytest.fixture(autouse=True)
def fake_keys(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("MOCK_KEY", "test-key")


def providers(server, tmp_path, budget=None):
    b = budget or Budget()
    return [AnthropicProvider("mock-claude", base_url=server.url, cache_dir=str(tmp_path / "c1"), budget=b),
            OpenAICompatProvider("mock-oss", base_url=server.url + "/v1", api_key_env="MOCK_KEY",
                                 cache_dir=str(tmp_path / "c2"), budget=b)]


def test_agent_loop_runs_on_both_wire_formats(server, tmp_path):
    task = TASK_BY_ID["summarize_budget_email"]
    for p in providers(server, tmp_path):
        r = run_trial(TrialSpec(p.label, "baseline", task.id, "benign", 0), task, Safeguards("baseline", []), p)
        assert [s["calls"][0]["tool"] for s in r["steps"][:2]] == ["list_emails", "read_email"], p.kind
        assert r["completed"] and r["stop"] == "final" and r["agent_in_tokens"] == 300


def test_anthropic_tool_results_are_grouped_and_schema_sent(server, tmp_path):
    p = providers(server, tmp_path)[0]
    task = TASK_BY_ID["summarize_budget_email"]
    run_trial(TrialSpec("a", "baseline", task.id, "benign", 0), task, Safeguards("baseline", []), p)
    last = server.state.bodies[-1]
    assert last["tools"][0]["input_schema"]["type"] == "object"
    roles = [m["role"] for m in last["messages"]]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
    assert last["messages"][2]["content"][0]["type"] == "tool_result"


def test_cache_replays_and_trials_are_independent_samples(server, tmp_path):
    p = providers(server, tmp_path)[0]
    msgs = [{"role": "user", "content": "hi"}]
    p.chat("s", msgs, [], sample_key="trial-0")
    hits = server.state.hits
    t = p.chat("s", msgs, [], sample_key="trial-0")
    assert t.cached and server.state.hits == hits          # replay is free
    p.chat("s", msgs, [], sample_key="trial-1")
    assert server.state.hits == hits + 1                     # a new trial is a new sample


def test_openai_seed_is_derived_per_trial(server, tmp_path):
    p = providers(server, tmp_path)[1]
    p.chat("s", [{"role": "user", "content": "hi"}], [], sample_key="a")
    p.chat("s", [{"role": "user", "content": "hi"}], [], sample_key="b")
    seeds = [b["seed"] for b in server.state.bodies[-2:]]
    assert seeds[0] != seeds[1]


def test_retries_on_rate_limit(server, tmp_path, monkeypatch):
    monkeypatch.setattr("agent_safety.providers.time.sleep", lambda s: None)
    p = providers(server, tmp_path)[0]
    server.state.fail_next = 2
    turn = p.chat("s", [{"role": "user", "content": "x"}], [], sample_key="r")
    assert turn.tool_calls and server.state.hits == 3


def test_budget_cap_stops_spending(server, tmp_path):
    b = Budget(max_usd=0.0005, prices={"mock-claude": (1.0, 5.0)})
    p = providers(server, tmp_path, b)[0]
    p.chat("s", [{"role": "user", "content": "x"}], [], sample_key="1")   # 100 in + 10 out = $0.00015
    p.chat("s", [{"role": "user", "content": "x"}], [], sample_key="2")
    p.chat("s", [{"role": "user", "content": "x"}], [], sample_key="3")
    with pytest.raises(BudgetExceeded):
        p.chat("s", [{"role": "user", "content": "x"}], [], sample_key="4")


def write_cfg(tmp_path, server, **extra):
    cfg = {"name": "t", "seed": 1, "trials": 1, "concurrency": 2, "cache_dir": str(tmp_path / "cache"),
           "tasks": ["summarize_budget_email", "reply_boss", "pay_invoice_vs_po"],
           "styles": ["direct", "multilingual"],
           "agents": [{"provider": "scripted", "policy": "naive"},
                      {"provider": "anthropic", "model": "mock-claude", "base_url": server.url, "name": "mock"}],
           "judge": {"provider": "openai_compat", "model": "mock-judge", "base_url": server.url + "/v1",
                     "temperature": 0},
           "configs": ["baseline", "regex_filter", "llm_screen", "llm_verifier", "layered_llm", "confirm_all"],
           "ablate": ["layered"]}
    cfg.update(extra)
    path = tmp_path / "exp.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def test_full_pipeline_with_judge_layers_and_resume(server, tmp_path):
    cfg = write_cfg(tmp_path, server)
    out = run(str(cfg), str(tmp_path / "out"), quiet=True)
    traces = [json.loads(x) for x in (out / "traces.jsonl").read_text().splitlines()]
    n = len(traces)
    assert n > 0 and not any(t["error"] for t in traces)
    llm_layer = [t for t in traces if t["config"] == "layered_llm" and t["model"] == "scripted:naive"
                 and t["kind"] == "attack"]
    assert llm_layer and all(not t["unsafe_executed"] for t in llm_layer)
    assert any(t["guard_in_tokens"] > 0 for t in llm_layer)
    summary = analyze(out)
    for f in ("summary.json", "report.md", "trials.csv", "hand_coding.csv", "dashboard.html"):
        assert (out / f).exists(), f
    assert summary["paired"] and summary["ablation"]
    html = (out / "dashboard.html").read_text()
    assert html.startswith("<!doctype html>") and "<\\/script" not in html.split('id="data"')[0]
    # resume: nothing new to run, file unchanged in length
    hits = server.state.hits
    run(str(cfg), str(tmp_path / "out"), quiet=True)
    assert len((out / "traces.jsonl").read_text().splitlines()) == n and server.state.hits == hits


def test_judge_configs_are_skipped_without_a_judge(server, tmp_path, capsys):
    cfg = write_cfg(tmp_path, server, judge=None, agents=[{"provider": "scripted", "policy": "robust"}])
    out = run(str(cfg), str(tmp_path / "o2"), quiet=True)
    cfgs = {json.loads(x)["config"] for x in (out / "traces.jsonl").read_text().splitlines()}
    assert "llm_screen" not in cfgs and "baseline" in cfgs
    assert "skipped" in capsys.readouterr().out


def test_dry_run_writes_nothing(server, tmp_path, capsys):
    cfg = write_cfg(tmp_path, server)
    run(str(cfg), str(tmp_path / "o3"), dry_run=True)
    assert not (tmp_path / "o3").exists() and "trials" in capsys.readouterr().out


def test_shipped_configs_parse():
    root = os.path.join(os.path.dirname(__file__), "..", "configs")
    from agent_safety.runner import build_plan, load_config
    for f in os.listdir(root):
        cfg = load_config(os.path.join(root, f))
        specs, guards, _ = build_plan(cfg, has_judge=bool(cfg.get("judge")))
        assert specs and guards, f
