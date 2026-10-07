import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.exceptions import SigmaConversionError
from tests.test_backend_elasticsearch_esql import esql_backend


def test_event_count_correlation_rule_stats_query(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1" and fieldB=="value2"
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_count=count() by timebucket, fieldC, fieldD
| where event_count >= 10"""
    ]


def test_event_count_correlation_rule_stats_query_no_group_field(
    esql_backend: ESQLBackend,
):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1" and fieldB=="value2"
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_count=count() by timebucket
| where event_count >= 10"""
    ]


def test_value_count_correlation_rule_stats_query(esql_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fieldD
            """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1" and fieldB=="value2"
| eval timebucket=date_trunc(15minutes, @timestamp) | stats value_count=count_distinct(fieldD) by timebucket, fieldC
| where value_count < 10"""
    ]


def test_temporal_correlation_rule_stats_query(esql_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where (fieldA=="value1" and fieldB=="value2") or (fieldA=="value3" and fieldB=="value4")
| eval event_type=case(fieldA=="value1" and fieldB=="value2", "base_rule_1", fieldA=="value3" and fieldB=="value4", "base_rule_2")
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_type_count=count_distinct(event_type) by timebucket, fieldC
| where event_type_count >= 2"""
    ]


def test_temporal_correlation_rule_set_state_index():
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
    product: product1
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
    product: product2
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert ESQLBackend(
        processing_pipeline=ProcessingPipeline.from_yaml(
        """
name: test
transformations:
    - id: set_state_index
      type: set_state
      key: index
      val: logs-product1-*
      rule_conditions:
        - type: logsource
          category: test
          product: product1
    - id: set_state_index
      type: set_state
      key: index
      val: logs-product2-*
      rule_conditions:
        - type: logsource
          category: test
          product: product2
"""
    )).convert(correlation_rule) == [
        """from logs-product1-*,logs-product2-* metadata _id, _index, _version | where (fieldA=="value1" and fieldB=="value2") or (fieldA=="value3" and fieldB=="value4")
| eval event_type=case(fieldA=="value1" and fieldB=="value2", "base_rule_1", fieldA=="value3" and fieldB=="value4", "base_rule_2")
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_type_count=count_distinct(event_type) by timebucket, fieldC
| where event_type_count >= 2"""
    ]


def test_event_count_correlation_with_fields_in_correlation_rule(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 10
fields:
    - fieldD
    - fieldE
        """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(5minutes, @timestamp) | stats event_count=count() by timebucket, fieldC
| where event_count >= 10"""
    ]


def test_event_count_correlation_with_fields_in_referenced_rule(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
fields:
    - fieldD
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 10
        """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(5minutes, @timestamp) | stats event_count=count(), fieldD=values(fieldD) by timebucket, fieldC
| where event_count >= 10"""
    ]


def test_event_count_correlation_fields_exclude_groupby(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
fields:
    - fieldC
    - fieldD
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 10
        """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(5minutes, @timestamp) | stats event_count=count(), fieldD=values(fieldD) by timebucket, fieldC
| where event_count >= 10"""
    ]


def test_event_count_correlation_no_fields_no_values(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 10
        """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(5minutes, @timestamp) | stats event_count=count() by timebucket, fieldC
| where event_count >= 10"""
    ]


def test_value_count_correlation_with_fields(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
fields:
    - fieldE
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        lt: 10
        field: fieldD
        """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(5minutes, @timestamp) | stats value_count=count_distinct(fieldD), fieldE=values(fieldE) by timebucket, fieldC
| where value_count < 10"""
    ]


def test_temporal_correlation_with_fields(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
fields:
    - fieldD
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value2
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 5m
        """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where (fieldA=="value1") or (fieldA=="value2")
| eval event_type=case(fieldA=="value1", "base_rule_1", fieldA=="value2", "base_rule_2")
| eval timebucket=date_trunc(5minutes, @timestamp) | stats event_type_count=count_distinct(event_type), fieldD=values(fieldD) by timebucket, fieldC
| where event_type_count >= 2"""
    ]


MV_CORRELATION_RULE = """
title: Failed logins
name: failed_login
status: test
logsource:
    category: test_category
detection:
    sel:
        fieldA: value1
    condition: sel
---
title: Many failed logins
status: test
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - fieldB
    timespan: 5m
    condition:
        gte: 3
"""


def test_esql_correlation_multivalue_field_in_base_rule():
    # The MV rewrite has to reach the correlation's embedded WHERE clause too.
    pipeline = ProcessingPipeline.from_yaml(
        """
name: mv
priority: 10
transformations:
  - id: mv
    type: set_state
    key: multivalue_fields
    val: [fieldA]
"""
    )
    query = ESQLBackend(pipeline).convert(SigmaCollection.from_yaml(MV_CORRELATION_RULE))[0]
    assert 'mv_intersects(fieldA, ["value1"])' in query
    assert 'fieldA=="value1"' not in query


METRIC_BASE_RULE = """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
"""


def metric_rule(correlation: str, fields: bool = False) -> SigmaCollection:
    return SigmaCollection.from_yaml(
        f"""
title: Metric correlation
status: test
correlation:
{correlation}
---{METRIC_BASE_RULE}"""
        + ("fields:\n    - fieldD\n" if fields else "")
    )


@pytest.mark.parametrize(
    "correlation_type,field,percentile,timespan,condition_op,threshold,aggregation",
    [
        ("value_sum", "bytes_out", None, "1h", "gt", 1000000, "sum(bytes_out)"),
        ("value_avg", "query_len", None, "10m", "gt", 50, "avg(query_len)"),
        ("value_percentile", "bytes_out", 95, "1h", "gt", 100000, "percentile(bytes_out, 95)"),
        ("value_median", "bytes_out", None, "1h", "lt", 500, "median(bytes_out)"),
    ],
)
def test_value_metric_correlation_rule(
    esql_backend: ESQLBackend,
    correlation_type,
    field,
    percentile,
    timespan,
    condition_op,
    threshold,
    aggregation,
):
    timebucket = {"1h": "1hours", "10m": "10minutes"}[timespan]
    query_op = {"gt": ">", "lt": "<"}[condition_op]
    percentile_line = f"\n        percentile: {percentile}" if percentile is not None else ""
    rule = metric_rule(
        f"""    type: {correlation_type}
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: {timespan}
    condition:
        field: {field}{percentile_line}
        {condition_op}: {threshold}"""
    )
    assert esql_backend.convert(rule) == [
        f"""from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc({timebucket}, @timestamp) | stats {correlation_type}={aggregation} by timebucket, fieldC
| where {correlation_type} {query_op} {threshold}"""
    ]


def test_value_percentile_requires_a_percentile(esql_backend: ESQLBackend):
    rule = metric_rule(
        """    type: value_percentile
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 1h
    condition:
        field: bytes_out
        gt: 100000"""
    )
    with pytest.raises(SigmaConversionError, match="Percentile must be specified"):
        esql_backend.convert(rule)


def test_value_sum_correlation_rule_no_group_field(esql_backend: ESQLBackend):
    rule = metric_rule(
        """    type: value_sum
    rules:
        - base_rule
    timespan: 1h
    condition:
        field: bytes_out
        gt: 10"""
    )
    assert esql_backend.convert(rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(1hours, @timestamp) | stats value_sum=sum(bytes_out) by timebucket
| where value_sum > 10"""
    ]


def test_value_avg_correlation_with_fields(esql_backend: ESQLBackend):
    rule = metric_rule(
        """    type: value_avg
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 1h
    condition:
        field: bytes_out
        gt: 10""",
        fields=True,
    )
    assert esql_backend.convert(rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1"
| eval timebucket=date_trunc(1hours, @timestamp) | stats value_avg=avg(bytes_out), fieldD=values(fieldD) by timebucket, fieldC
| where value_avg > 10"""
    ]


WINDOW_GROUPED = """    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 10m
    condition:
        gte: 5"""

GRID_10M = "mv_dedupe(mv_append(mv_append(date_trunc(10minutes, @timestamp), date_trunc(10minutes, @timestamp - 150 seconds) + 150 seconds), mv_append(date_trunc(10minutes, @timestamp - 300 seconds) + 300 seconds, date_trunc(10minutes, @timestamp - 450 seconds) + 450 seconds)))"


@pytest.mark.parametrize(
    "correlation_type,condition,aggregation,comparison",
    [
        ("event_count", "gte: 5", "count()", ">= 5"),
        ("value_count", "field: fieldD\n        gte: 5", "count_distinct(fieldD)", ">= 5"),
        ("value_sum", "field: bytes_out\n        gt: 5", "sum(bytes_out)", "> 5"),
    ],
)
def test_window_correlation_rule(
    esql_backend: ESQLBackend, correlation_type, condition, aggregation, comparison
):
    rule = metric_rule(
        f"""    type: {correlation_type}
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 10m
    condition:
        {condition}""",
        fields=True,
    )
    name = correlation_type
    assert esql_backend.convert(rule, correlation_method="window") == [
        f"""from * metadata _id, _index, _version | where fieldA=="value1"
| where fieldC is not null
| where @timestamp is not null
| eval w = {GRID_10M}
| mv_expand w
| stats {name}={aggregation}, window_start=min(@timestamp), @timestamp=max(@timestamp), event.ingested=max(event.ingested), fieldD=values(fieldD) by w, fieldC
| where {name} {comparison}
| stats {name}=max({name}), window_start=min(window_start), @timestamp=max(@timestamp), event.ingested=max(event.ingested), fieldD=values(fieldD) by fieldC
| where @timestamp is not null
| sort {name} desc"""
    ]


def test_window_correlation_drops_events_missing_a_group_by_field(esql_backend: ESQLBackend):
    rule = metric_rule(WINDOW_GROUPED.replace("        - fieldC\n", "        - fieldC\n        - x-real-ip\n"), fields=True)
    lines = esql_backend.convert(rule, correlation_method="window")[0].split("\n")
    assert lines[1] == "| where fieldC is not null and `x-real-ip` is not null"
    assert lines[-3].endswith("by fieldC, `x-real-ip`")


def test_window_correlation_quotes_field_names(esql_backend: ESQLBackend):
    correlation = WINDOW_GROUPED.replace("event_count", "value_count").replace("gte: 5", "field: x-real-ip\n        gte: 5")
    rule = SigmaCollection.from_yaml(
        f"""
title: Metric correlation
status: test
correlation:
{correlation}
---{METRIC_BASE_RULE}fields:
    - x-forwarded-for
"""
    )
    query = esql_backend.convert(rule, correlation_method="window")[0]
    assert "| stats value_count=count_distinct(`x-real-ip`)," in query
    assert "`x-forwarded-for`=values(`x-forwarded-for`) by w, fieldC" in query


def test_window_correlation_rule_no_group_by(esql_backend: ESQLBackend):
    rule = metric_rule(WINDOW_GROUPED.replace("    group-by:\n        - fieldC\n", ""), fields=True)
    assert esql_backend.convert(rule, correlation_method="window") == [
        f"""from * metadata _id, _index, _version | where fieldA=="value1"
| where @timestamp is not null
| eval w = {GRID_10M}
| mv_expand w
| stats event_count=count(), window_start=min(@timestamp), @timestamp=max(@timestamp), event.ingested=max(event.ingested), fieldD=values(fieldD) by w
| where event_count >= 5
| stats event_count=max(event_count), window_start=min(window_start), @timestamp=max(@timestamp), event.ingested=max(event.ingested), fieldD=values(fieldD)
| where @timestamp is not null
| sort event_count desc"""
    ]


def test_window_correlation_short_timespan_counts_each_window_once(esql_backend: ESQLBackend):
    rule = metric_rule(WINDOW_GROUPED.replace("timespan: 10m", "timespan: 3s"), fields=True)
    query = esql_backend.convert(rule, correlation_method="window")[0]
    assert "| eval w = mv_dedupe(mv_append(mv_append(date_trunc(3seconds, @timestamp)," in query
    assert "date_trunc(3seconds, @timestamp - 0 seconds) + 0 seconds" in query


@pytest.mark.parametrize(
    "correlation_type,condition,aggregation,comparison",
    [
        ("event_count", "lt: 5", "count()", "< 5"),
        ("event_count", "lte: 5", "count()", "<= 5"),
        ("event_count", "eq: 5", "count()", "== 5"),
        ("value_count", "field: fieldD\n        neq: 5", "count_distinct(fieldD)", "!= 5"),
        ("value_avg", "field: bytes_out\n        gt: 5", "avg(bytes_out)", "> 5"),
        (
            "value_percentile",
            "field: bytes_out\n        percentile: 95\n        gte: 5",
            "percentile(bytes_out, 95)",
            ">= 5",
        ),
        ("value_median", "field: bytes_out\n        gt: 5", "median(bytes_out)", "> 5"),
    ],
)
def test_window_correlation_falls_back_to_a_trailing_window(
    correlation_type, condition, aggregation, comparison
):
    """ A partial window at a run's edge could meet these conditions, so they count one complete window. """
    rule = metric_rule(
        f"""    type: {correlation_type}
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 10m
    condition:
        {condition}""",
        fields=True,
    )
    backend = ESQLBackend(query_delay="30", correlation_allowance="600")
    name = correlation_type
    order = "asc" if comparison.startswith("<") else "desc"
    assert backend.convert(rule, correlation_method="window") == [
        f"""from * metadata _id, _index, _version | where fieldA=="value1"
| where fieldC is not null
| where @timestamp >= now() - 1230 seconds and @timestamp < now() - 630 seconds
| stats {name}={aggregation}, window_start=min(@timestamp), @timestamp=max(@timestamp), event.ingested=max(event.ingested), fieldD=values(fieldD) by fieldC
| where {name} {comparison}
| where @timestamp is not null
| sort {name} {order}"""
    ]


def test_trailing_window_defaults_to_no_offset(esql_backend: ESQLBackend):
    rule = metric_rule(WINDOW_GROUPED.replace("gte: 5", "lt: 5").replace("    group-by:\n        - fieldC\n", ""))
    lines = esql_backend.convert(rule, correlation_method="window")[0].split("\n")
    assert lines[1] == "| where @timestamp >= now() - 600 seconds and @timestamp < now() - 0 seconds"
    assert lines[2].endswith("event.ingested=max(event.ingested)")


def test_trailing_window_temporal_types_events(esql_backend: ESQLBackend):
    rule = SigmaCollection.from_yaml(
        """
title: Temporal
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 10m
    condition:
        eq: 1
---
title: Base 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: a
    condition: selection
---
title: Base 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: b
    condition: selection
"""
    )
    lines = esql_backend.convert(rule, correlation_method="window")[0].split("\n")
    assert lines[1] == '| eval event_type_0=case(fieldA=="a", 1), event_type_1=case(fieldA=="b", 1)'
    assert lines[4].startswith("| stats event_type_0=count(event_type_0), event_type_1=count(event_type_1), window_start=")
    assert lines[5] == "| eval event_type_count=case(event_type_0 > 0, 1, 0) + case(event_type_1 > 0, 1, 0)"
    # the flags stay out of the alert
    assert lines[6] == "| drop event_type_0, event_type_1"
    assert lines[7] == "| where event_type_count == 1"


def test_window_correlation_temporal_types_before_the_grids(esql_backend: ESQLBackend):
    rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value2
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 1h
"""
    )
    query = esql_backend.convert(rule, correlation_method="window")[0]
    lines = query.split("\n")
    assert lines[1] == '| eval event_type_0=case(fieldA=="value1", 1), event_type_1=case(fieldA=="value2", 1)'
    assert lines[2] == "| where fieldC is not null"
    assert lines[3] == "| where @timestamp is not null"
    assert "date_trunc(1hours, @timestamp - 900 seconds) + 900 seconds" in query
    assert lines[6].startswith("| stats event_type_0=count(event_type_0), event_type_1=count(event_type_1), window_start=")
    # an event matching both rules counts for each
    assert lines[7] == "| eval event_type_count=case(event_type_0 > 0, 1, 0) + case(event_type_1 > 0, 1, 0)"
    assert lines[8] == "| where event_type_count >= 2"
    assert "| stats event_type_count=max(event_type_count)" in query


def test_window_correlation_temporal_typing_avoids_the_match_operator():
    rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        tags: dns
        fieldA: 'a : "b'
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        tags: conn
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 1h
"""
    )
    backend = ESQLBackend(multivalue_fields=["tags"], multivalue_match_operator=True)
    lines = backend.convert(rule, correlation_method="window")[0].split("\n")
    # EVAL rejects `:`
    assert lines[0].endswith('| where (tags : "dns" and fieldA=="a : \\"b") or (tags : "conn")')
    assert lines[1] == (
        '| eval event_type_0=case(mv_intersects(tags, ["dns"]) and fieldA=="a : \\"b", 1),'
        ' event_type_1=case(mv_intersects(tags, ["conn"]), 1)'
    )


def test_window_correlation_percentile_required(esql_backend: ESQLBackend):
    rule = metric_rule(
        """    type: value_percentile
    rules:
        - base_rule
    timespan: 10m
    condition:
        field: bytes_out
        gt: 5""",
        fields=True,
    )
    with pytest.raises(SigmaConversionError, match="Percentile must be specified"):
        esql_backend.convert(rule, correlation_method="window")


CASE_FOLDED = """    type: value_count
    rules:
        - base_rule
    group-by:
        - user.name
        - source.ip
    timespan: 10m
    condition:
        field: fieldD
        {condition}"""


def test_case_insensitive_window_groups_lowercased_with_spellings():
    """ Windows records an account as typed, so Admin and admin must count together. """
    rule = metric_rule(CASE_FOLDED.format(condition="gte: 5"))
    lines = ESQLBackend(case_insensitive=True).convert(rule, correlation_method="window")[0].split("\n")
    assert lines[5] == (
        "| stats value_count=count_distinct(to_lower(to_string(fieldD))), window_start=min(@timestamp),"
        " @timestamp=max(@timestamp), event.ingested=max(event.ingested), user.name_spellings=values(user.name)"
        " by w, folded_0=to_lower(to_string(user.name)), source.ip"
    )
    assert lines[7] == (
        "| stats value_count=max(value_count), window_start=min(window_start), @timestamp=max(@timestamp),"
        " event.ingested=max(event.ingested), user.name_spellings=values(user.name_spellings) by folded_0, source.ip"
    )
    assert lines[8] == "| rename folded_0 as user.name"


def test_case_insensitive_trailing_groups_lowercased_with_spellings():
    rule = metric_rule(CASE_FOLDED.format(condition="lt: 5"))
    lines = ESQLBackend(case_insensitive=True).convert(rule, correlation_method="window")[0].split("\n")
    assert lines[3].endswith(
        ", user.name_spellings=values(user.name) by folded_0=to_lower(to_string(user.name)), source.ip"
    )
    assert lines[4] == "| rename folded_0 as user.name"
    assert lines[5] == "| where value_count < 5"
    # the quietest groups are the matches, so a row limit must keep them
    assert lines[-1] == "| sort value_count asc"


def test_case_folding_skips_exempt_fields():
    rule = metric_rule(CASE_FOLDED.format(condition="gte: 5"))
    backend = ESQLBackend(case_insensitive=True, case_insensitive_exempt_fields=["user.name", "fieldD"])
    query = backend.convert(rule, correlation_method="window")[0]
    assert "folded_" not in query
    assert "_spellings" not in query
    assert "count_distinct(fieldD)" in query


def test_case_sensitive_groups_unchanged(esql_backend: ESQLBackend):
    query = esql_backend.convert(metric_rule(CASE_FOLDED.format(condition="gte: 5")), correlation_method="window")[0]
    assert "folded_" not in query
    assert "by w, user.name, source.ip" in query
