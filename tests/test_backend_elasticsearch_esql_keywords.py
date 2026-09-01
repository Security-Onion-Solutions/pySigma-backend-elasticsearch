"""ES|QL field-less keyword detections.

A Sigma keyword detection has no field and means "this string appears anywhere
in the event".  Upstream raises NotImplementedError (99 of the 3,328 rules
Security Onion deploys); the EQL backend emits a bare string literal, which is
not valid EQL either -- all 98 that convert fail at execution with
"must be [boolean], found value [...] type [keyword]".

Every expected string here was executed against Elasticsearch 9.4.5 and
round-tripped against documents containing the literal.
"""

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


def _rule(*values, condition="kw"):
    listing = "\n".join(f"        - {v}" for v in values)
    return f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    kw:
{listing}
    sel:
        fieldA: 'x'
    condition: {condition}
"""


def convert(backend, *values, condition="kw"):
    return backend.convert(
        SigmaCollection.from_yaml(_rule(*values, condition=condition))
    )[0]


def search(regex, phrase=None):
    """The pair of QSTR arms the backend emits for one keyword value.

    A Lucene regexp matches per analyzed token, so it cannot match a `text`
    field; a quoted phrase cannot match a `keyword` field.  Both are emitted.
    A value carrying a wildcard has no phrase arm, since a phrase query cannot
    express one.
    """
    r = f'qstr("{regex}")'
    if phrase is None:
        return r
    p = phrase.replace("\\", "\\\\").replace('"', '\\\\\\"')
    return f'({r} or qstr("\\"{p}\\""))'


# Basic emission


def test_keyword_becomes_qstr(esql_backend):
    # A single alphanumeric token needs no phrase arm: the analyzer produces
    # that same token, so the regexp arm already matches an analyzed field.
    assert convert(esql_backend, "'whoami'") == PRE + search("/.*whoami.*/")


def test_keywords_or_together(esql_backend):
    assert convert(esql_backend, "'samr'", "'lsarpc'") == PRE + (
        search("/.*samr.*/") + " or " + search("/.*lsarpc.*/")
    )


def test_keyword_can_be_negated(esql_backend):
    # The deployed corpus uses keyword blocks as filters more often than as
    # selections, so `not qstr(...)` has to be valid.  It is.
    q = convert(esql_backend, "'samr'", condition="sel and not kw")
    # QSTR is already null-safe, so a negated keyword block needs no wrapper --
    # and ES|QL rejects one outright ("[QSTR] function can't be used with COALESCE").
    assert q == PRE + 'fieldA=="x" and not ' + search("/.*samr.*/")


def test_numeric_keyword(esql_backend):
    assert convert(esql_backend, "1234") == PRE + search("/.*1234.*/")


# Escaping.  A query_string wildcard term would end at the first space and
# treat `-`, `:`, `(` and `"` as operators; inside /.../ only `/` delimits.


@pytest.mark.parametrize(
    "value,expected",
    [
        ("'dpapi::masterkey'", "/.*dpapi::masterkey.*/"),
        (
            "'New-MailboxExportRequest -Mailbox '",
            "/.*New-MailboxExportRequest -Mailbox .*/",
        ),
        ("'a+b'", "/.*a\\\\+b.*/"),
        ("'dot.dot'", "/.*dot\\\\.dot.*/"),
        ("'x[y]z'", "/.*x\\\\[y\\\\]z.*/"),
        ("'(){:;};'", "/.*\\\\(\\\\)\\\\{:;\\\\};.*/"),
        ("'hash#tag'", "/.*hash\\\\#tag.*/"),
        ("'amp&and'", "/.*amp\\\\&and.*/"),
        ("'lt<gt>'", "/.*lt\\\\<gt\\\\>.*/"),
        ("'tilde~here'", "/.*tilde\\\\~here.*/"),
    ],
)
def test_regex_metacharacters_are_escaped(esql_backend, value, expected):
    # Only the regexp arm is asserted here; the phrase arm is covered separately.
    q = convert(esql_backend, value)
    assert f'qstr("{expected}")' in q


def test_forward_slash_is_escaped(esql_backend):
    # `/` closes the regexp inside query_string, so it must not reach it raw.
    assert 'qstr("/.*\\\\/Basic\\\\/Command\\\\/.*/")' in convert(
        esql_backend, "'/Basic/Command/'"
    )


def test_quote_survives_both_layers(esql_backend):
    # Two layers: regexp escape, then the ES|QL string literal.  Applying them
    # in the wrong order is what broke LIKE and RLIKE upstream.
    assert 'qstr("/.*say\\\\\\"hi.*/")' in convert(esql_backend, "'say\"hi'")


def test_backslash_survives_both_layers(esql_backend):
    assert 'qstr("/.*back\\\\\\\\slash.*/")' in convert(esql_backend, "'back\\\\slash'")


# Sigma wildcards


def test_wildcards_map_to_regex(esql_backend):
    assert convert(esql_backend, "'Trojan*FOUND'") == PRE + search(
        "/.*Trojan.*FOUND.*/"
    )


def test_single_wildcard_maps_to_dot(esql_backend):
    assert convert(esql_backend, "'q?mark'") == PRE + search("/.*q.mark.*/")


def test_escaped_wildcard_is_literal(esql_backend):
    assert convert(esql_backend, "'q\\?mark'") == PRE + search(
        "/.*q\\\\?mark.*/", "q?mark"
    )


# Matching against default_field `*` is case-sensitive, and neither analyze_wildcard
# nor KQL's case_insensitive fixes it, so the regexp folds case per character.


def test_case_folding_off_by_default(esql_backend):
    assert convert(esql_backend, "'Whoami'") == PRE + search("/.*Whoami.*/")


def test_case_folding_on(esql_backend_ci):
    assert convert(esql_backend_ci, "'whoami'") == PRE + (
        search("/.*[wW][hH][oO][aA][mM][iI].*/")
    )


def test_case_folding_leaves_non_letters_alone(esql_backend_ci):
    assert convert(esql_backend_ci, "'a-1_b'") == PRE + search(
        "/.*[aA]-1_[bB].*/", "a-1_b"
    )


def test_case_folding_does_not_split_an_escape(esql_backend_ci):
    # The fold runs over already-escaped text; it must skip the character after
    # a backslash, or `\.` would become `\[.]` and change meaning.
    assert convert(esql_backend_ci, "'a.b'") == PRE + search(
        "/.*[aA]\\\\.[bB].*/", "a.b"
    )


def test_case_folding_does_not_touch_wildcards(esql_backend_ci):
    assert convert(esql_backend_ci, "'a*b'") == PRE + search("/.*[aA].*[bB].*/")
