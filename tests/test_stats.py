import math

from agent_safety.stats import binom_two_sided, cluster_bootstrap, holm, mcnemar_exact, wilson


def test_wilson_known_values():
    lo, hi = wilson(5, 10)
    assert math.isclose(lo, 0.2366, abs_tol=1e-3) and math.isclose(hi, 0.7634, abs_tol=1e-3)
    assert wilson(0, 0) == (0.0, 1.0)
    assert wilson(0, 20)[0] == 0.0 and wilson(20, 20)[1] == 1.0


def test_cluster_bootstrap_is_wider_when_trials_are_correlated():
    # 10 tasks, 10 trials each; outcomes perfectly correlated within a task
    vals, clusters = [], []
    for t in range(10):
        for _ in range(10):
            vals.append(float(t < 5))
            clusters.append(f"t{t}")
    mean, lo, hi = cluster_bootstrap(vals, clusters)
    wlo, whi = wilson(50, 100)
    assert mean == 0.5 and (hi - lo) > (whi - wlo)


def test_mcnemar_and_binomial():
    assert binom_two_sided(0, 0) == 1.0
    assert math.isclose(binom_two_sided(0, 10), 2 / 1024)
    r = mcnemar_exact([(True, False)] * 10 + [(True, True)] * 5)
    assert r["a_only"] == 10 and r["b_only"] == 0 and r["p"] < 0.01
    assert mcnemar_exact([(True, True), (False, False)])["p"] == 1.0


def test_holm_is_monotone_and_conservative():
    adj = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj["a"] == 0.03 and adj["c"] == 0.06 and adj["b"] == 0.06
