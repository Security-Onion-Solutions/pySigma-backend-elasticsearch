"""ES|QL escaping, multivalue and case-folding behaviour.

Every expected string here was executed against Elasticsearch 9.4.5; the
comments record what the server does with the alternative rendering.
"""

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.processing.pipeline import ProcessingPipeline

PRE = "from * metadata _id, _index, _version | where "


@pytest.fixture
def esql_backend():
    return ESQLBackend()


def _rule(detection: str) -> str:
    return f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
{detection}
    condition: sel
"""


def convert(backend, detection):
    return backend.convert(SigmaCollection.from_yaml(_rule(detection)))


# LIKE escaping


def test_like_backslash_is_double_escaped(esql_backend):
    # One layer (`*\\Windows\\*`) reaches LIKE as *\Windows\* -> "escape character
    # is not followed by special wildcard char" -> hard error.
    assert convert(
        esql_backend, "    sel:\n        fieldA|contains: '\\Windows\\System32\\'"
    ) == [PRE + 'fieldA like "*\\\\\\\\Windows\\\\\\\\System32\\\\\\\\*"']


def test_like_literal_asterisk_is_escaped_once(esql_backend):
    # A Sigma-escaped `\*` is a literal asterisk. It must reach LIKE as \* so the
    # engine treats it literally; `not ... like "*\\*"` otherwise reads as
    # "contains no literal asterisk" and matches every document.
    assert convert(esql_backend, "    sel:\n        fieldA|contains: '\\*'") == [
        PRE + 'fieldA like "*\\\\**"'
    ]


def test_like_literal_question_mark_is_escaped(esql_backend):
    assert convert(esql_backend, "    sel:\n        fieldA|contains: '\\?'") == [
        PRE + 'fieldA like "*\\\\?*"'
    ]


def test_wildcards_are_not_escaped_outside_like(esql_backend):
    # ==, IN, starts_with and ends_with give * and ? no meaning, so escaping them
    # emits \* inside a string literal, which is not a valid ES|QL escape.
    assert convert(esql_backend, "    sel:\n        fieldA: '\\\\\\\\\\*\\\\IPC$'") == [
        PRE + 'fieldA=="\\\\\\\\*\\\\IPC$"'
    ]


def test_startswith_and_endswith_are_unaffected(esql_backend):
    assert convert(
        esql_backend, "    sel:\n        fieldA|startswith: 'C:\\Windows'"
    ) == [PRE + 'starts_with(fieldA, "C:\\\\Windows")']
    assert convert(esql_backend, "    sel:\n        fieldA|endswith: '\\cmd.exe'") == [
        PRE + 'ends_with(fieldA, "\\\\cmd.exe")'
    ]


# RLIKE


def test_rlike_unanchored_pattern_is_wrapped(esql_backend):
    # Sigma |re is PCRE substring matching; RLIKE is Lucene regexp and must match
    # the whole value. rlike "foo.*bar" misses "xxfoo123barxx"; the wrapped form
    # does not.
    assert convert(esql_backend, "    sel:\n        fieldA|re: 'foo.*bar'") == [
        PRE + 'fieldA rlike ".*foo.*bar.*"'
    ]


def test_rlike_anchors_are_consumed(esql_backend):
    assert convert(esql_backend, "    sel:\n        fieldA|re: '^foo$'") == [
        PRE + 'fieldA rlike "foo"'
    ]
    assert convert(esql_backend, "    sel:\n        fieldA|re: '^foo'") == [
        PRE + 'fieldA rlike "foo.*"'
    ]


def test_rlike_quote_needs_both_layers(esql_backend):
    # Escaping the quote after doubling the escape char leaves rlike "...\"",
    # which reaches the regex engine as a bare quote -> invalid regex pattern.
    assert convert(esql_backend, "    sel:\n        fieldA|re: 'noexit.+\"'") == [
        PRE + 'fieldA rlike ".*noexit.+\\\\\\".*"'
    ]


def test_rlike_backslash_class_survives(esql_backend):
    assert convert(esql_backend, "    sel:\n        fieldA|re: '-k\\s\\w{1,64}'") == [
        PRE + 'fieldA rlike ".*-k\\\\s\\\\w{1,64}.*"'
    ]


# Multivalued fields

MV_PIPELINE = ProcessingPipeline.from_yaml("""
name: mv
priority: 10
transformations:
  - id: mv
    type: set_state
    key: multivalue_fields
    val: [event.type, tags, process.args]
""")


@pytest.fixture
def mv_backend():
    return ESQLBackend(MV_PIPELINE)


def test_multivalue_equality_uses_mv_intersects(mv_backend):
    # Scalar == against an array column returns null and the row is dropped.
    assert convert(mv_backend, "    sel:\n        event.type: 'start'") == [
        PRE + 'mv_intersects(event.type, ["start"])'
    ]


def test_multivalue_value_list_collapses_to_one_call(mv_backend):
    assert convert(
        mv_backend,
        "    sel:\n        event.type:\n            - 'start'\n            - 'end'",
    ) == [PRE + 'mv_intersects(event.type, ["start", "end"])']


def test_non_multivalue_field_keeps_scalar_equality(mv_backend):
    assert convert(mv_backend, "    sel:\n        host.os.type: 'windows'") == [
        PRE + 'host.os.type=="windows"'
    ]


def test_multivalue_contains_uses_padded_join(mv_backend):
    # LIKE returns null on an array and there is no MV_LIKE before ES 9.6.
    # The separator is a real \x01, which survives Go yaml.v3 -> PyYAML round-trip.
    assert convert(mv_backend, "    sel:\n        tags|contains: 'notice'") == [
        PRE + 'concat("\x01", mv_concat(tags, "\x01"), "\x01") like "*notice*"'
    ]


def test_multivalue_endswith_anchors_on_the_separator(mv_backend):
    assert convert(mv_backend, "    sel:\n        tags|endswith: 'onn'") == [
        PRE + 'concat("\x01", mv_concat(tags, "\x01"), "\x01") like "*onn\x01*"'
    ]


def test_multivalue_startswith_anchors_on_the_separator(mv_backend):
    assert convert(mv_backend, "    sel:\n        tags|startswith: 'co'") == [
        PRE + 'concat("\x01", mv_concat(tags, "\x01"), "\x01") like "*\x01co*"'
    ]


def test_multivalue_fields_accept_globs():
    pipeline = ProcessingPipeline.from_yaml("""
name: mv
priority: 10
transformations:
  - id: mv
    type: set_state
    key: multivalue_fields
    val: ['event.*']
""")
    assert convert(ESQLBackend(pipeline), "    sel:\n        event.action: 'exec'") == [
        PRE + 'mv_intersects(event.action, ["exec"])'
    ]


def test_multivalue_fields_from_constructor_option():
    backend = ESQLBackend(multivalue_fields=["event.type"])
    assert convert(backend, "    sel:\n        event.type: 'start'") == [
        PRE + 'mv_intersects(event.type, ["start"])'
    ]


# Case-insensitive matching


@pytest.fixture
def ci_backend():
    return ESQLBackend(case_insensitive=True)


def test_case_insensitive_equality(ci_backend):
    assert convert(ci_backend, "    sel:\n        fieldA: 'CMD.exe'") == [
        PRE + 'to_lower(fieldA)=="cmd.exe"'
    ]


def test_case_insensitive_like(ci_backend):
    assert convert(ci_backend, "    sel:\n        fieldA|contains: 'System32'") == [
        PRE + 'to_lower(fieldA) like "*system32*"'
    ]


def test_case_insensitive_startswith(ci_backend):
    # LIKE, not STARTS_WITH: a prefix function around TO_LOWER defeats the pushdown.
    # The backslash is escaped twice -- string literal, then LIKE pattern.
    assert convert(
        ci_backend, "    sel:\n        fieldA|startswith: 'C:\\Windows'"
    ) == [PRE + 'to_lower(fieldA) like "c:\\\\\\\\windows*"']


def test_case_insensitive_endswith(ci_backend):
    assert convert(ci_backend, "    sel:\n        fieldA|endswith: '\\WhoAmI.exe'") == [
        PRE + 'to_lower(fieldA) like "*\\\\\\\\whoami.exe"'
    ]


def test_case_insensitive_equality_stays_eq(ci_backend):
    # == is pushed down under TO_LOWER, so it is left alone.
    assert convert(ci_backend, "    sel:\n        fieldA: 'CMD.exe'") == [
        PRE + 'to_lower(fieldA)=="cmd.exe"'
    ]


def test_case_insensitive_skips_caseless_subfields(ci_backend):
    # .caseless is lowercase-normalised at index time; wrapping it is redundant.
    assert convert(
        ci_backend, "    sel:\n        process.executable.caseless: 'C:\\X.exe'"
    ) == [PRE + 'process.executable.caseless=="c:\\\\x.exe"']


def test_case_insensitive_is_off_by_default(esql_backend):
    assert convert(esql_backend, "    sel:\n        fieldA: 'CMD.exe'") == [
        PRE + 'fieldA=="CMD.exe"'
    ]


def test_default_multivalue_fields_apply_without_configuration(esql_backend):
    # ECS array fields are covered out of the box; a pipeline only has to declare
    # non-ECS fields.
    assert convert(esql_backend, "    sel:\n        event.type: 'start'") == [
        PRE + 'mv_intersects(event.type, ["start"])'
    ]


def test_default_multivalue_fields_leave_scalar_fields_alone(esql_backend):
    assert convert(esql_backend, "    sel:\n        host.os.type: 'windows'") == [
        PRE + 'host.os.type=="windows"'
    ]


def test_pipeline_state_extends_rather_than_replaces_the_default():
    pipeline = ProcessingPipeline.from_yaml("""
name: mv
priority: 10
transformations:
  - id: mv
    type: set_state
    key: multivalue_fields
    val: [custom.field]
""")
    backend = ESQLBackend(pipeline)
    assert convert(backend, "    sel:\n        custom.field: 'x'") == [
        PRE + 'mv_intersects(custom.field, ["x"])'
    ]
    # the shipped defaults are still in effect
    assert convert(backend, "    sel:\n        event.type: 'start'") == [
        PRE + 'mv_intersects(event.type, ["start"])'
    ]


def test_case_insensitive_string_option_values():
    """sigma-cli passes -O values as strings; "false" must not enable it."""
    from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend

    for value, expected in (
        ("true", True),
        ("True", True),
        ("1", True),
        (True, True),
        ("false", False),
        ("False", False),
        ("0", False),
        (False, False),
        (None, False),
    ):
        assert ESQLBackend(case_insensitive=value).case_insensitive is expected, value


def test_case_insensitive_skips_non_string_fields(ci_backend):
    """TO_LOWER rejects non-strings, and Sigma quotes values on ip/boolean fields.

    A boolean or numeric literal additionally loses its quotes, so the comparison
    is native rather than a coercion: `destination.port=="445"` is a hard error
    ("first argument is [numeric] so second argument must also be [numeric]"),
    and while ES|QL does accept `exists=="true"`, the unquoted form is what the
    field actually holds.  An `ip` literal keeps its quotes -- ES|QL coerces the
    string itself, and `source.ip==10.0.0.1` is a parse error.
    """
    assert convert(ci_backend, "    sel:\n        source.ip: '10.0.0.1'") == [
        PRE + 'source.ip=="10.0.0.1"'
    ]
    assert convert(
        ci_backend, "    sel:\n        dll.code_signature.exists: 'true'"
    ) == [PRE + "dll.code_signature.exists==true"]
    assert convert(ci_backend, "    sel:\n        destination.port: '445'") == [
        PRE + "destination.port==445"
    ]


@pytest.mark.parametrize(
    "value",
    ["nan", "inf", "-inf", "infinity", "1_000"],
)
def test_numeric_field_keeps_quotes_for_non_esql_literals(ci_backend, value):
    """float() accepts these; ES|QL rejects every one of them unquoted."""
    assert convert(ci_backend, f"    sel:\n        destination.port: '{value}'") == [
        PRE + f'to_string(destination.port)=="{value}"'
    ]


def test_case_insensitive_still_wraps_string_fields(ci_backend):
    """The exempt list must not swallow ordinary string fields."""
    assert convert(ci_backend, "    sel:\n        process.name: 'CMD.exe'") == [
        PRE + 'to_lower(process.name)=="cmd.exe"'
    ]


def test_case_insensitive_exempt_fields_extensible():
    """Pipeline state extends, and does not replace, the built-in list."""
    from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
    from sigma.processing.pipeline import ProcessingPipeline

    pipeline = ProcessingPipeline.from_yaml("""
        name: Test
        priority: 30
        transformations:
          - id: exempt
            type: set_state
            key: case_insensitive_exempt_fields
            val:
              - custom.numeric_field
        """)
    backend = ESQLBackend(pipeline, case_insensitive=True)
    assert convert(backend, "    sel:\n        custom.numeric_field: '42'") == [
        PRE + 'custom.numeric_field=="42"'
    ]
    # built-ins survive alongside the state-declared entry
    assert convert(backend, "    sel:\n        source.ip: '10.0.0.1'") == [
        PRE + 'source.ip=="10.0.0.1"'
    ]
