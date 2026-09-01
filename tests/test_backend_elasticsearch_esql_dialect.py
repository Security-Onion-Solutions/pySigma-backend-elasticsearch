"""PCRE->Lucene regex translation, and string values landing on typed fields.

Both classes were silent: ES|QL accepted the query and matched nothing.
Every behaviour asserted here was verified against Elasticsearch 9.4.5.
"""

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend

PRE = "from * metadata _id, _index, _version | where "


@pytest.fixture
def backend():
    return ESQLBackend()


@pytest.fixture
def backend_ci():
    return ESQLBackend(case_insensitive=True)


def convert(be, detection):
    return be.convert(SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
{detection}
    condition: sel
"""))[0]


# Translatable PCRE constructs


@pytest.mark.parametrize(
    "pcre,lucene",
    [
        # `?` after `(` is a literal in Lucene, so this searched for "?:ab"
        (".*(?:ab).*", ".*(ab).*"),
        # likewise "?iab"; folded to classes instead
        (".*(?i)abc.*", ".*[aA][bB][cC].*"),
        # & is Lucene's intersection operator
        (".*a&b.*", ".*a\\&b.*"),
        (".*a<b.*", ".*a\\<b.*"),
        (".*a#b.*", ".*a\\#b.*"),
        # Lucene reads a+? as (a+)? = a*, so PCRE's "at least one" was lost
        (".*a+?b.*", ".*a+b.*"),
        (".*a*?b.*", ".*a*b.*"),
        # \n is rejected outright; \s is the nearest expressible superset
        (".*a\\nb.*", ".*a\\sb.*"),
        # inside a character class it must stay bare -- bracketing it there nests
        # a class, which Lucene accepts and never matches
        (".*[a\\n]b.*", ".*[a\\s]b.*"),
        (".*[\\t\\r]b.*", ".*[\\s\\s]b.*"),
    ],
)
def test_regex_is_translated(backend, pcre, lucene):
    assert backend.translate_regex_to_lucene(pcre) == lucene


def test_widened_escape_never_nests_a_character_class(backend):
    out = backend.translate_regex_to_lucene(".*[a\\n]b.*")
    assert "[[" not in out and "]]" not in out


def test_inline_flag_folds_inside_character_classes(backend):
    assert backend.translate_regex_to_lucene(".*(?i)a[bc]d.*") == ".*[aA][bBcC][dD].*"


def test_inline_flag_applies_only_after_itself(backend):
    assert backend.translate_regex_to_lucene(".*a(?i)b.*") == ".*a[bB].*"


def test_escaped_operators_are_left_alone(backend):
    assert backend.translate_regex_to_lucene(".*a\\&b.*") == ".*a\\&b.*"


# Untranslatable constructs must raise, not silently match nothing


@pytest.mark.parametrize(
    "pcre",
    [
        ".*\\babc.*",
        ".*abc\\B.*",
        ".*(ab)\\1.*",
        ".*a(?=b).*",
        ".*a(?!b).*",
        ".*(?<=a)b.*",
    ],
)
def test_untranslatable_regex_raises(backend, pcre):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        backend.translate_regex_to_lucene(pcre)


# Anchoring must not change the meaning of a top-level alternation


def test_alternation_is_grouped_before_anchoring(backend):
    # `.*foo|bar.*` parses as `(.*foo)|(bar.*)` and matches neither "xxfooxx"
    # nor "xxbarxx"; verified on 9.4.5.
    assert backend.anchor_regex("foo|bar") == ".*(foo|bar).*"


def test_already_grouped_alternation_is_untouched(backend):
    assert backend.anchor_regex("(foo|bar)") == ".*(foo|bar).*"


def test_alternation_inside_a_class_is_not_top_level(backend):
    assert backend.anchor_regex("a[b|c]d") == ".*a[b|c]d.*"


def test_fully_anchored_pattern_loses_its_anchors(backend):
    assert backend.anchor_regex("^abc$") == "abc"


# String values landing on ip / numeric / boolean fields


def test_wildcard_against_ip_field_uses_to_string(backend_ci):
    # Was: argument of [destination.ip like "127.*"] must be [string]
    assert convert(backend_ci, "        destination.ip: '127.*'") == PRE + (
        'to_string(destination.ip) like "127.*"'
    )


def test_non_ip_literal_against_ip_field_uses_to_string(backend_ci):
    # Was: Cannot convert string [-] to [IP]
    assert (
        convert(backend_ci, "        source.ip: '-'")
        == PRE + 'to_string(source.ip)=="-"'
    )


def test_valid_ip_literal_stays_a_native_comparison(backend_ci):
    # ES|QL coerces a well-formed address literal to `ip` itself, and that form
    # pushes down; wrapping it in TO_STRING would only cost the pushdown.
    assert convert(backend_ci, "        source.ip: '127.0.0.1'") == PRE + (
        'source.ip=="127.0.0.1"'
    )


def test_quoted_number_against_numeric_field_is_unquoted(backend_ci):
    # Was: first argument of [source.port=="0"] is [numeric]. Kept native rather
    # than stringified, so the comparison still pushes down.
    assert convert(backend_ci, "        source.port: '0'") == PRE + "source.port==0"


def test_quoted_boolean_against_boolean_field_is_unquoted(backend_ci):
    assert convert(
        backend_ci, "        process.code_signature.valid: 'true'"
    ) == PRE + ("process.code_signature.valid==true")


def test_string_fields_are_unaffected(backend_ci):
    assert convert(backend_ci, "        process.executable: 'x'") == PRE + (
        'to_lower(process.executable)=="x"'
    )


def test_typed_fields_are_never_case_folded(backend_ci):
    # TO_LOWER on an ip/numeric field is itself a type error; the exemption list
    # and the type map describe the same set of fields.
    q = convert(backend_ci, "        source.port: '0'")
    assert "to_lower" not in q
