"""Semantic defects found by running the deployed ruleset against ground-truth
documents on Elasticsearch 9.4.5.  Each test pins a fix whose absence produced
valid queries that silently returned the wrong rows.
"""

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend

PRE = "from * metadata _id, _index, _version | where "


@pytest.fixture
def backend():
    return ESQLBackend()


@pytest.fixture
def backend_ci():
    return ESQLBackend(case_insensitive=True)


def convert(be, detection, condition="sel"):
    return be.convert(SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
{detection}
    condition: {condition}
"""))[0]


# Null-safe negation: NOT(NULL) is NULL, so `not filter` dropped documents
# whose filter field was absent. Guarded at the leaf, not with COALESCE.


def test_negation_is_null_safe(backend):
    q = convert(
        backend,
        "    sel:\n        fieldA: 'a'\n    filt:\n        fieldB: 'b'",
        condition="sel and not filt",
    )
    assert q == PRE + 'fieldA=="a" and not (fieldB is not null and fieldB=="b")'


def test_negated_group_is_null_safe(backend):
    q = convert(
        backend,
        "    sel:\n        fieldA: 'a'\n    filt:\n        fieldB: 'b'\n        fieldC: 'c'",
        condition="sel and not filt",
    )
    assert q == PRE + (
        'fieldA=="a" and not ((fieldB is not null and fieldB=="b")'
        ' and (fieldC is not null and fieldC=="c"))'
    )


def test_negation_null_safe_under_case_insensitivity(backend_ci):
    q = convert(
        backend_ci,
        "    sel:\n        fieldA: 'a'\n    filt:\n        fieldB: 'B'",
        condition="sel and not filt",
    )
    assert q == PRE + (
        'to_lower(fieldA)=="a" and not (fieldB is not null and to_lower(fieldB)=="b")'
    )


def test_positive_leaf_is_not_wrapped(backend):
    # The guard exists only to make a negation behave; a positive match already
    # requires the field to be present.
    q = convert(
        backend,
        "    sel:\n        fieldA: 'a'\n    filt:\n        fieldB: 'b'",
        condition="sel and filt",
    )
    assert q == PRE + 'fieldA=="a" and fieldB=="b"'


def test_in_list_leaf_is_null_strict_too(backend_ci):
    q = convert(
        backend_ci,
        "    sel:\n        fieldA: 'a'\n    filt:\n        fieldB:\n            - 'b'\n            - 'c'",
        condition="sel and not filt",
    )
    assert "fieldB is not null" in q


def test_negated_keyword_needs_no_guard(backend):
    # QSTR returns a real boolean rather than null, and ES|QL refuses to let it
    # near COALESCE, so it must be left alone.
    q = convert(
        backend,
        "    sel:\n        fieldA: 'a'\n    kw:\n        - 'samr'",
        condition="sel and not kw",
    )
    assert q == PRE + 'fieldA=="a" and not qstr("/.*samr.*/")'


def test_null_check_is_still_emitted_plainly(backend):
    q = convert(backend, "    sel:\n        fieldA: null")
    assert q == PRE + "fieldA is null"


# The IN path bypassed case-folding, making `case_insensitive` a no-op on the
# most common Sigma construct.


def test_in_list_is_case_folded(backend_ci):
    q = convert(
        backend_ci,
        "    sel:\n        fieldA:\n            - 'Cmd.Exe'\n            - 'PowerShell.EXE'",
    )
    assert q == PRE + 'to_lower(fieldA) in ("cmd.exe", "powershell.exe")'


def test_in_list_untouched_without_case_insensitivity(backend):
    q = convert(
        backend,
        "    sel:\n        fieldA:\n            - 'Cmd.Exe'\n            - 'PowerShell.EXE'",
    )
    assert q == PRE + 'fieldA in ("Cmd.Exe", "PowerShell.EXE")'


def test_in_list_matches_the_single_value_path(backend_ci):
    # A one-value list and a scalar must fold identically; before the fix a list
    # of two folded only once a wildcard appeared in it.
    single = convert(backend_ci, "    sel:\n        fieldA: 'Cmd.Exe'")
    assert 'to_lower(fieldA)=="cmd.exe"' in single


def test_in_list_on_multivalue_field_still_uses_mv_intersects(backend_ci):
    q = convert(
        backend_ci, "    sel:\n        tags:\n            - 'A'\n            - 'B'"
    )
    assert q == PRE + 'mv_intersects(to_lower(tags), ["a", "b"])'


# PrivilegeList is multivalued wherever it exists (2,367 of 2,367 documents
# measured), so a scalar comparison returned null on every one of them.


def test_privilege_list_is_treated_as_multivalue(backend):
    q = convert(
        backend, "    sel:\n        winlog.event_data.PrivilegeList: 'SeDebugPrivilege'"
    )
    assert (
        q
        == PRE + 'mv_intersects(winlog.event_data.PrivilegeList, ["SeDebugPrivilege"])'
    )


# A regexp matches per analyzed token and a phrase is the mirror image, so
# both arms are emitted to cover keyword and text mappings.


def test_keyword_emits_regexp_and_phrase(backend):
    q = convert(backend, "    kw:\n        - 'dpapi::masterkey'", condition="kw")
    assert (
        q == PRE + '(qstr("/.*dpapi::masterkey.*/") or qstr("\\"dpapi::masterkey\\""))'
    )


def test_keyword_phrase_arm_carries_original_case(backend_ci):
    # The regexp arm folds case per character; the phrase arm does not need to,
    # because an analyzed field folds case on both sides at index time.
    q = convert(backend_ci, "    kw:\n        - 'Kiwi Legit'", condition="kw")
    assert 'qstr("\\"Kiwi Legit\\"")' in q
    assert "[kK][iI][wW][iI]" in q


def test_keyword_with_wildcard_has_no_phrase_arm(backend):
    # A phrase query cannot express a wildcard, so such a value keeps only the
    # regexp arm rather than gaining a wrong one.
    q = convert(backend, "    kw:\n        - 'wget * perl'", condition="kw")
    assert q == PRE + 'qstr("/.*wget .* perl.*/")'


def test_keyword_phrase_arm_escapes_quotes(backend):
    q = convert(backend, "    kw:\n        - 'say\"hi'", condition="kw")
    assert q.endswith('or qstr("\\"say\\\\\\"hi\\""))')


# Guarding the leaf keeps the pushdown, so a LIKE ending in `~` no longer needs
# the carve-out COALESCE forced.


def test_trailing_tilde_keeps_like(backend_ci):
    q = convert(backend_ci, "    sel:\n        fieldA|endswith: '.c~'")
    assert q == PRE + 'to_lower(fieldA) like "*.c~"'


def test_interior_tilde_still_uses_like(backend_ci):
    q = convert(backend_ci, "    sel:\n        fieldA|contains: 'a~b'")
    assert q == PRE + 'to_lower(fieldA) like "*a~b*"'


def test_ordinary_suffix_still_uses_like_for_pushdown(backend_ci):
    q = convert(backend_ci, "    sel:\n        fieldA|endswith: '.exe'")
    assert q == PRE + 'to_lower(fieldA) like "*.exe"'
