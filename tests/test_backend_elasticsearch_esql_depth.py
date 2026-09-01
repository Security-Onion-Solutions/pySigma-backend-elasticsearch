"""ES|QL boolean grouping and the 300-expression-depth limit.

ES|QL rejects an expression nested deeper than 300.  pySigma emits a long
OR-run flat, which the parser builds left-deep, so depth tracks the term count
and a rule with a few hundred values is a hard failure.  The backend
re-parenthesises long runs into a balanced tree; OR and AND are associative, so
the predicate is unchanged and only its grouping differs.

Every ceiling quoted here was measured against Elasticsearch 9.4.5.
"""

import re

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend

PRE = "from * metadata _id, _index, _version | where "


@pytest.fixture
def esql_backend():
    return ESQLBackend()


@pytest.fixture
def esql_backend_ci():
    return ESQLBackend(case_insensitive=True)


def _rule(values, modifier="|contains"):
    listing = "\n".join(f"            - 'v{v}'" for v in values)
    return f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA{modifier}:
{listing}
    condition: sel
"""


def convert(backend, values, modifier="|contains"):
    return backend.convert(SigmaCollection.from_yaml(_rule(values, modifier)))[0]


def max_paren_depth(query: str) -> int:
    """Nesting depth of the emitted expression, which is what ES|QL counts."""
    depth = best = 0
    for ch in query:
        if ch == "(":
            depth += 1
            best = max(best, depth)
        elif ch == ")":
            depth -= 1
    return best


# Short runs are untouched


def test_short_or_run_is_emitted_flat(esql_backend):
    # At or below boolean_group_size the output is byte-identical to upstream,
    # so the fix cannot perturb the rules that already worked.
    q = convert(esql_backend, range(3))
    assert q == PRE + ('fieldA like "*v0*" or fieldA like "*v1*" or fieldA like "*v2*"')
    assert max_paren_depth(q) == 0


def test_run_at_group_size_is_still_flat(esql_backend):
    q = convert(esql_backend, range(ESQLBackend.boolean_group_size))
    assert " or " in q
    assert max_paren_depth(q) == 0


# Long runs are balanced


def test_long_or_run_is_balanced(esql_backend):
    q = convert(esql_backend, range(ESQLBackend.boolean_group_size + 1))
    assert max_paren_depth(q) > 0


def test_depth_grows_logarithmically(esql_backend):
    # Flat emission gives depth == n; ES|QL rejects past 300.
    q = convert(esql_backend, range(1000))
    assert q.count(" or ") == 999
    assert max_paren_depth(q) < 20


def test_all_terms_survive_regrouping(esql_backend):
    # Regrouping must not drop or duplicate a term.
    n = 500
    q = convert(esql_backend, range(n))
    for v in range(n):
        assert f'"*v{v}*"' in q
    assert q.count(" like ") == n


def test_and_runs_are_balanced_too(esql_backend):
    values = "\n".join(f"        field{i}: 'v{i}'" for i in range(200))
    rule = f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
{values}
    condition: sel
"""
    q = esql_backend.convert(SigmaCollection.from_yaml(rule))[0]
    assert q.count(" and ") == 199
    assert max_paren_depth(q) < 20


# Interaction with case-insensitivity


def test_to_lower_does_not_deepen_per_term(esql_backend, esql_backend_ci):
    # TO_LOWER nests inside each leaf, costing one level in total, not one per term.
    plain = convert(esql_backend, range(500))
    ci = convert(esql_backend_ci, range(500))
    assert "to_lower(fieldA)" in ci
    assert max_paren_depth(ci) - max_paren_depth(plain) <= 1


def test_balanced_grouping_applies_under_case_insensitivity(esql_backend_ci):
    q = convert(esql_backend_ci, range(1000))
    assert q.count(" or ") == 999
    assert max_paren_depth(q) < 20


# Exact-value lists still collapse to IN, which is depth-flat


def test_plain_value_list_still_uses_in(esql_backend):
    # IN is genuinely depth-flat (8,192+ terms measured), so exact-value lists
    # must keep collapsing rather than becoming a balanced OR tree.
    q = convert(esql_backend, range(100), modifier="")
    assert " in (" in q
    assert " or " not in q


# The cap above which balancing is not worth it


def test_run_over_the_automaton_budget_is_left_flat(esql_backend):
    # Over budget, balancing only buys a query the circuit breaker rejects anyway.
    # The budget is in characters because automaton size, not term count, is the bound.
    values = ["v%s%s" % (i, "x" * 200) for i in range(2000)]
    q = convert(esql_backend, values)
    assert max_paren_depth(q) == 0


def test_long_but_cheap_run_is_still_balanced(esql_backend):
    # Many short terms stay well inside the budget and must keep the regrouping,
    # since the depth limit is what would otherwise reject them.
    q = convert(esql_backend, range(3000))
    assert sum(len(p) for p in q.split(" or ")) < ESQLBackend.boolean_max_balanced_chars
    assert max_paren_depth(q) > 0
