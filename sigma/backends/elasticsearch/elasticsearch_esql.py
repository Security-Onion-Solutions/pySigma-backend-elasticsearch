from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.conversion.base import TextQueryBackend
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import (
    SigmaCompareExpression,
    SigmaString,
    SpecialChars,
    SigmaRegularExpression,
    SigmaNull,
)
import sigma
import re
import json
import math
import fnmatch
import ipaddress
from typing import ClassVar, Dict, Tuple, Pattern, List, Iterable, Optional, Union


class ESQLBackend(TextQueryBackend):
    """ES|QL backend."""

    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "ES|QL backend"
    formats: Dict[str, str] = {
        "default": "Plain ES|QL queries",
        "kibana_ndjson": "Kibana ES|QL queries in NDJSON Format.",
        "siem_rule": "Elastic Security ES|QL queries as SIEM Rules in JSON Format.",
        "siem_rule_ndjson": "Elastic Security ES|QL queries as SIEM Rules in NDJSON Format.",
    }
    requires_pipeline: bool = True

    query_expression: ClassVar[str] = "{query}"
    state_defaults: ClassVar[Dict[str, str]] = {
        "index": "*",
        "metadata": "_id, _index, _version",
        "keep": "",
    }

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = (
        "=="  # Token inserted between field and value (without separator)
    )

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = (
        "`"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^[\\w.]+$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ## Values
    str_quote: ClassVar[str] = (
        '"'  # string quoting character (added as escaping character)
    )
    escape_char: ClassVar[str] = (
        "\\"  # Escaping character for special characters inside string
    )
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "?"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = (
        "\\"  # Characters quoted in addition to wildcards and string quote
    )
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "starts_with({field}, {value})"
    endswith_expression: ClassVar[str] = "ends_with({field}, {value})"
    wildcard_match_expression: ClassVar[str] = (
        "{field} like {value}"  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = '{field} rlike "{regex}"'
    re_escape_char: ClassVar[str] = (
        "\\"  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[Tuple[str]] = ('"',)  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression: ClassVar[str] = (
        'cidr_match({field}, "{value}")'  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only).
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[str] = (
        "{field1}=={field2}"  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[str] = (
        "{field} is null"  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = (
        "{field} is not null"  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str] = (
        "{field} is null"  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    list_separator: ClassVar[str] = ", "  # List element separator

    # Correlations
    correlation_methods: ClassVar[Dict[str, str]] = {
        "stats": "Correlation with stats command",
    }
    default_correlation_method: ClassVar[str] = "stats"
    default_correlation_query: ClassVar[str] = {
        "stats": "{search}\n{aggregate}\n{condition}"
    }
    temporal_correlation_query: ClassVar[str] = {
        "stats": "{search}\n{typing}\n{aggregate}\n{condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = "({query})"
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " or "

    typing_expression: ClassVar[str] = "| eval event_type=case({queries})"
    typing_rule_query_expression: ClassVar[str] = '{query}, "{ruleid}"'
    typing_rule_query_expression_joiner: ClassVar[str] = ", "

    # not yet supported for ES|QL because all queries from correlated rules are combined into one query.
    # correlation_search_field_normalization_expression: ClassVar[str] = " | rename {field} as {alias}"
    # correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats event_count=count(){fields}{groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats value_count=count_distinct({field}){fields}{groupby}"
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats event_type_count=count_distinct(event_type){fields}{groupby}"
    }

    correlation_fields_expression: ClassVar[Dict[str, str]] = {"stats": "{fields}"}
    correlation_fields_field_expression: ClassVar[Dict[str, str]] = {
        "stats": ", {field}=values({field})"
    }
    correlation_fields_field_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ""}

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "s": "seconds",
        "m": "minutes",
        "h": "hours",
        "d": "days",
        "w": "weeks",
        "M": "months",
        "y": "years",
    }
    referenced_rules_expression: ClassVar[Dict[str, str]] = {"stats": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ","}

    groupby_expression_nofield: ClassVar = {"stats": " by timebucket"}
    groupby_expression: ClassVar[Dict[str, str]] = {"stats": " by timebucket{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"stats": ", {field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ""}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where event_type_count {op} {count}"
    }

    def convert_correlation_aggregation_fields_from_template(
        self,
        correlation_rule_fields: list[str],
        referenced_rules: list,
        group_by: Optional[list[str]],
        method: str,
    ) -> str:
        if self.correlation_fields_expression is None:
            return ""
        all_fields = []
        for rl in referenced_rules:
            for fld in rl.rule.fields:
                if (group_by is None or fld not in group_by) and fld not in all_fields:
                    all_fields.append(fld)
        if (
            len(all_fields) == 0
            or self.correlation_fields_field_expression is None
            or self.correlation_fields_field_expression_joiner is None
        ):
            return ""
        return self.correlation_fields_expression[method].format(
            fields=self.correlation_fields_field_expression_joiner[method].join(
                (
                    self.correlation_fields_field_expression[method].format(
                        field=self.escape_and_quote_field(field)
                    )
                    for field in all_fields
                )
            )
        )

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        multivalue_fields: Optional[Iterable[str]] = None,
        case_insensitive: bool = False,
        case_insensitive_exempt_fields: Optional[Iterable[str]] = None,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.schedule_interval = schedule_interval
        self.schedule_interval_unit = schedule_interval_unit
        # Fields known to hold several values per document.  Unioned with the
        # pipeline state key of the same name; entries may be globs.
        self.multivalue_fields = list(multivalue_fields or [])
        self.case_insensitive_exempt_fields = list(case_insensitive_exempt_fields or [])
        # sigma-cli passes -O values as strings, where "false" is truthy.
        self.case_insensitive = (
            case_insensitive.strip().lower() in ("true", "yes", "1")
            if isinstance(case_insensitive, str)
            else bool(case_insensitive)
        )
        self._null_strict_depth = 0
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99,
        }

    def flatten_list_of_indices(
        self, nested_list: List[Union[str, List[str]]]
    ) -> List[str]:
        flat_list = []
        for item in nested_list:
            if isinstance(item, list):
                flat_list.extend(
                    self.flatten_list_of_indices(item)
                )  # Recursively flatten the sublist
            else:
                flat_list.append(item)  # Append the string
        return flat_list

    def preprocess_indices(self, indices: List[str]) -> str:
        if not indices:
            return self.state_defaults["index"]

        if self.wildcard_multi in indices:
            return self.wildcard_multi

        indices = self.flatten_list_of_indices(nested_list=indices)
        if len(indices) == 1:
            return indices[0]

        indices = list(set(indices))  # Deduplicate

        # Sort the indices to ensure a consistent order as sets are arbitrary ordered
        indices.sort()

        return ",".join(indices)

    def finish_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        state: ConversionState,
    ) -> Union[str, DeferredQueryExpression]:
        # If set, load the index from the processing state
        index_state = (
            state.processing_state.get("index", self.state_defaults["index"])
            if isinstance(rule, SigmaRule)
            else [
                state.processing_state.get("index", self.state_defaults["index"])
                for rule_reference in rule.rules
                for state in rule_reference.rule.get_conversion_states()
            ]
        )
        # If the non-default index is not a string, preprocess it
        if not isinstance(index_state, str):
            index_state = self.preprocess_indices(index_state)

        # Save the processed index back to the processing state
        state.processing_state["index"] = index_state

        return query

    # LIKE applies two escape layers (string literal, then the LIKE pattern itself);
    # the inherited conversion applies only the first. Wrong for LIKE, and in a
    # negated filter it inverts the meaning. Built from SigmaString parts so each
    # layer is applied once.

    like_wildcard_multi: ClassVar[str] = "*"
    like_wildcard_single: ClassVar[str] = "?"
    like_escape_char: ClassVar[str] = "\\"

    def escape_like_literal_text(self, text: str) -> str:
        """Escape plain text for the LIKE pattern layer (not the string literal layer)."""
        out = []
        for ch in text:
            if ch in (
                self.like_escape_char,
                self.like_wildcard_multi,
                self.like_wildcard_single,
            ):
                out.append(self.like_escape_char)
            out.append(ch)
        return "".join(out)

    def convert_value_like(self, s: SigmaString, state: ConversionState) -> str:
        """Render a SigmaString as a quoted ES|QL LIKE pattern with both escape layers."""
        pattern = []
        for part in s.s:
            if part is SpecialChars.WILDCARD_MULTI:
                pattern.append(self.like_wildcard_multi)
            elif part is SpecialChars.WILDCARD_SINGLE:
                pattern.append(self.like_wildcard_single)
            else:
                pattern.append(self.escape_like_literal_text(str(part)))
        pattern = "".join(pattern)
        # now the string-literal layer
        literal = pattern.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{literal}"'

    def _selects_wildcard_match(self, v: SigmaString) -> bool:
        """Mirror of TextQueryBackend.convert_condition_field_eq_val_str branch selection:
        True only when the LIKE branch is the one that will be taken."""
        if not v.contains_special():
            return False
        if (
            self.startswith_expression is not None
            and v.endswith(SpecialChars.WILDCARD_MULTI)
            and (
                self.startswith_expression_allow_special
                or not v[:-1].contains_special()
            )
        ):
            return False
        if (
            self.endswith_expression is not None
            and v.startswith(SpecialChars.WILDCARD_MULTI)
            and (self.endswith_expression_allow_special or not v[1:].contains_special())
        ):
            return False
        if (
            self.contains_expression is not None
            and v.startswith(SpecialChars.WILDCARD_MULTI)
            and v.endswith(SpecialChars.WILDCARD_MULTI)
            and (
                self.contains_expression_allow_special or not v[1:-1].contains_special()
            )
        ):
            return False
        return self.wildcard_match_expression is not None

    def convert_condition_field_eq_val_str(self, cond, state):
        v = cond.value
        kind = self.field_type(cond.field, state)
        if kind is not None and isinstance(v, SigmaString):
            return self._convert_eq_val_typed(cond, v, kind, state)
        if isinstance(v, SigmaString) and self._selects_wildcard_match(v):
            if self.is_multivalue_field(cond.field, state):
                return self.wildcard_match_expression.format(
                    field=self._mv_joined_field(cond.field, state),
                    value=self._mv_like_pattern(v, state),
                    backend=self,
                )
            return self.wildcard_match_expression.format(
                field=self._ci_field(cond.field, state),
                value=self._ci_value(self.convert_value_like(v, state)),
                backend=self,
            )
        if isinstance(v, SigmaString) and self.is_multivalue_field(cond.field, state):
            if v.contains_special():
                # startswith / endswith against a multivalued field
                return self.wildcard_match_expression.format(
                    field=self._mv_joined_field(cond.field, state),
                    value=self._mv_like_pattern(v, state),
                    backend=self,
                )
            return self._mv_match(cond.field, [self.convert_value_str(v, state)], state)
        if self.case_insensitive and isinstance(v, SigmaString):
            # startswith/endswith/eq all take the field as first operand
            return self._convert_eq_val_str_ci(cond, state)
        return super().convert_condition_field_eq_val_str(cond, state)

    def _convert_eq_val_typed(self, cond, v: SigmaString, kind: str, state):
        """A string value landing on a non-string field."""
        plain = str(v)
        if not v.contains_special() and self._literal_matches_type(plain, kind):
            # `ip` keeps its quotes -- ES|QL coerces the string; source.ip==10.0.0.1
            # is a parse error.
            value = self.convert_value_str(v, state) if kind == "ip" else plain
            return self.eq_expression.format(
                field=self.escape_and_quote_field(cond.field), value=value, backend=self
            )
        field = self._typed_field(cond.field, state)
        if self._selects_wildcard_match(v) or v.contains_special():
            return self.wildcard_match_expression.format(
                field=field, value=self.convert_value_like(v, state), backend=self
            )
        return self.eq_expression.format(
            field=field, value=self.convert_value_str(v, state), backend=self
        )

    def _convert_eq_val_str_ci(self, cond, state):
        # STARTS_WITH/ENDS_WITH under TO_LOWER cannot push to Lucene and scan every
        # document; LIKE can. == and LIKE already push down, so only these are rewritten.
        v = cond.value
        field = self._ci_field(cond.field, state)
        if self.wildcard_match_expression is not None and (
            v.startswith(SpecialChars.WILDCARD_MULTI)
            or v.endswith(SpecialChars.WILDCARD_MULTI)
        ):
            return self.wildcard_match_expression.format(
                field=field,
                value=self._ci_value(self.convert_value_like(v, state)),
                backend=self,
            )
        return self.eq_expression.format(
            field=field,
            value=self._ci_value(self.convert_value_str(v, state)),
            backend=self,
        )

    # The base implementation bypasses _ci_field/_ci_value, making case_insensitive
    # a silent no-op on the most common Sigma construct.
    def convert_condition_as_in_expression(self, cond, state):
        args = getattr(cond, "args", [])
        field = getattr(args[0], "field", None) if args else None
        if not field or not isinstance(cond, ConditionOR):
            return super().convert_condition_as_in_expression(cond, state)
        raw = []
        for arg in args:
            val = getattr(arg, "value", None)
            if not isinstance(val, SigmaString):
                return super().convert_condition_as_in_expression(cond, state)
            raw.append(val)
        kind = self.field_type(field, state)
        if kind is not None:
            if all(
                not v.contains_special() and self._literal_matches_type(str(v), kind)
                for v in raw
            ):
                values = [
                    self.convert_value_str(v, state) if kind == "ip" else str(v)
                    for v in raw
                ]
                rendered = self.field_in_list_expression.format(
                    field=self.escape_and_quote_field(field),
                    op=self.or_in_operator,
                    list=self.list_separator.join(values),
                )
            else:
                # Per-value path knows how to wrap the field in TO_STRING.
                return self.convert_condition_or(cond, state)
        elif self.is_multivalue_field(field, state):
            rendered = self._mv_match(
                field, [self.convert_value_str(v, state) for v in raw], state
            )
        else:
            rendered = self.field_in_list_expression.format(
                field=self._ci_field(field, state),
                op=self.or_in_operator,
                list=self.list_separator.join(
                    self._ci_value(self.convert_value_str(v, state)) for v in raw
                ),
            )
        return self._make_null_strict(field, rendered, None)

    # A flat OR-run parses left-deep and hits ES|QL's depth limit of 300; balancing
    # it makes depth log2(n). See KNOWN_ISSUES.md "Expression depth limit".

    boolean_group_size: ClassVar[int] = 32

    # In characters, not terms: Lucene's automaton scales with total pattern text.
    # Over budget the run is left flat, so it fails at parse instead of costing real work.
    boolean_max_balanced_chars: ClassVar[int] = 131072

    def _balanced_join(self, args: List[str], token: str) -> str:
        if sum(len(a) for a in args) > self.boolean_max_balanced_chars:
            return (self.token_separator + token + self.token_separator).join(args)
        return self._balanced_join_inner(args, token)

    def _balanced_join_inner(self, args: List[str], token: str) -> str:
        joiner = self.token_separator + token + self.token_separator
        if len(args) <= self.boolean_group_size:
            return joiner.join(args)
        mid = len(args) // 2
        return self.group_expression.format(
            expr=self._balanced_join_inner(args[:mid], token)
            + joiner
            + self._balanced_join_inner(args[mid:], token)
        )

    def _convert_condition_args(self, cond, state) -> List[str]:
        return [
            converted
            for converted in (
                (
                    self.convert_condition(arg, state)
                    if self.compare_precedence(cond, arg)
                    else self.convert_condition_group(arg, state)
                )
                for arg in cond.args
            )
            if converted is not None
            and not isinstance(converted, DeferredQueryExpression)
        ]

    # ES|QL is three-valued: NOT(NULL) is NULL and WHERE keeps only TRUE, so
    # `not filter` dropped documents whose field was absent; Sigma says those match.
    # Fixed at the leaf -- COALESCE blocks the pushdown and ES|QL rejects it over QSTR.

    null_strict_expression: ClassVar[str] = "{field} is not null and {expr}"

    def _null_strict(self) -> bool:
        return self._null_strict_depth > 0

    def _make_null_strict(self, field: Optional[str], expr: str, cond) -> str:
        """Force a leaf to FALSE rather than NULL when its field is absent."""
        if not self._null_strict() or not field:
            return expr
        if isinstance(getattr(cond, "value", None), SigmaNull):
            return expr  # `is null` is already null-safe; wrapping inverts it
        return self.group_expression.format(
            expr=self.null_strict_expression.format(
                field=self.escape_and_quote_field(field), expr=expr
            )
        )

    def convert_condition_field_eq_val(self, cond, state):
        expr = super().convert_condition_field_eq_val(cond, state)
        if isinstance(expr, str):
            return self._make_null_strict(getattr(cond, "field", None), expr, cond)
        return expr

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState):
        arg = cond.args[0]
        if arg is None:
            return None
        self._null_strict_depth += 1
        try:
            if arg.__class__ in self.precedence:
                converted = self.convert_condition_group(arg, state)
            else:
                converted = self.convert_condition(arg, state)
                if isinstance(converted, DeferredQueryExpression):
                    return converted.negate()
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")
        finally:
            self._null_strict_depth -= 1
        if converted is None or isinstance(converted, DeferredQueryExpression):
            return converted
        return self.not_token + self.token_separator + converted

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState):
        try:
            args = self._convert_condition_args(cond, state)
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")
        if not args:
            return self.empty_or_expression
        return self._balanced_join(args, self.or_token)

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState):
        try:
            args = self._convert_condition_args(cond, state)
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")
        if not args:
            return self.empty_and_expression
        return self._balanced_join(args, self.and_token)

    # Same two layers as LIKE, in the wrong order upstream: the quote escape is
    # added after the escape char is doubled, so its own backslash never is.
    # Order here is regex layer, then string literal.

    re_escape: ClassVar[Tuple[str, ...]] = ()  # handled in convert_value_re instead
    re_escape_escape_char: bool = False

    # Sigma is PCRE, RLIKE is Lucene RegExp, and the differences are silent -- the
    # engine matches nothing. See KNOWN_ISSUES.md "Regular expressions".

    # Metacharacters are syntax a translated pattern keeps; operators are Lucene-only
    # punctuation PCRE treats as literal, so they are escaped on the way in.
    lucene_regex_metacharacters: ClassVar[str] = ".?+*|{}[]()" + chr(92)
    lucene_regex_operators: ClassVar[str] = "&<>#@~"
    # No Lucene equivalent.  \n, \t and \r are handled separately by widening.
    lucene_regex_untranslatable: ClassVar[Dict[str, str]] = {
        "b": "word boundary \\b",
        "B": "non-word-boundary \\B",
        "A": "start anchor \\A",
        "Z": "end anchor \\Z",
        "z": "end anchor \\z",
        "G": "match anchor \\G",
    }

    def _fold_regex_char(self, ch: str, in_class: bool) -> str:
        if not ("a" <= ch <= "z" or "A" <= ch <= "Z"):
            return ch
        if in_class:
            return ch.lower() + ch.upper()
        return f"[{ch.lower()}{ch.upper()}]"

    def translate_regex_to_lucene(self, rx: str) -> str:
        """Rewrite a PCRE pattern into the Lucene dialect, or raise."""
        out = []
        i = 0
        in_class = False
        fold = False
        while i < len(rx):
            c = rx[i]
            if c == "\\" and i + 1 < len(rx):
                nxt = rx[i + 1]
                if nxt in self.lucene_regex_untranslatable:
                    raise SigmaFeatureNotSupportedByBackendError(
                        f"Lucene regexp has no equivalent for "
                        f"{self.lucene_regex_untranslatable[nxt]}"
                    )
                if nxt.isdigit() and nxt != "0":
                    raise SigmaFeatureNotSupportedByBackendError(
                        "Lucene regexp does not support backreferences"
                    )
                if nxt in "ntr":
                    # Lucene rejects these; \s is the nearest superset. Bare in both
                    # positions -- bracketed inside a class it nests one and never matches.
                    out.append("\\s")
                    i += 2
                    continue
                out.append(c + nxt)
                i += 2
                continue
            if in_class:
                if c == "]":
                    in_class = False
                    out.append(c)
                else:
                    out.append(self._fold_regex_char(c, True) if fold else c)
                i += 1
                continue
            if c == "[":
                in_class = True
                out.append(c)
                i += 1
                continue
            if c == "(":
                if rx[i : i + 4] == "(?i)":
                    fold = True  # applies to the remainder, as in PCRE
                    i += 4
                    continue
                if rx[i : i + 3] in ("(?=", "(?!") or rx[i : i + 4] in ("(?<=", "(?<!"):
                    raise SigmaFeatureNotSupportedByBackendError(
                        "Lucene regexp does not support lookaround"
                    )
                if rx[i : i + 3] == "(?:":
                    out.append("(")  # Lucene has no non-capturing form
                    i += 3
                    continue
                out.append(c)
                i += 1
                continue
            if c == "?" and out and out[-1] and out[-1][-1] in "*+}":
                i += 1  # lazy quantifier: same language, drop it
                continue
            if c in self.lucene_regex_operators:
                out.append("\\" + c)
                i += 1
                continue
            out.append(self._fold_regex_char(c, False) if fold else c)
            i += 1
        if in_class:  # pragma: no cover - malformed input
            raise SigmaFeatureNotSupportedByBackendError("unterminated character class")
        return "".join(out)

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> str:
        regex_text = r.escape((), self.re_escape_char, False, self.re_flag_prefix)
        regex_text = self.translate_regex_to_lucene(regex_text)
        regex_text = self.anchor_regex(regex_text)
        # regex layer: a literal quote must reach the regex engine as \"
        regex_text = regex_text.replace('"', '\\"')
        # string-literal layer: backslashes first, then quotes
        literal = regex_text.replace("\\", "\\\\").replace('"', '\\"')
        return literal

    # Only LIKE gives * and ? meaning in ES|QL; ==, IN, starts_with and ends_with
    # treat them literally. Escaping them there emits \* , not a valid escape.

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        converted = s.convert(
            self.escape_char,
            None,  # * is not special outside LIKE
            None,  # ? is not special outside LIKE
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )
        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        return converted

    # Scalar == against a multivalued column returns null and the row is dropped --
    # a silent miss. Sigma value lists are OR, so membership is the right semantics.
    # MV_INTERSECTS over MV_CONTAINS: the latter returns TRUE for a null needle.

    mv_match_expression: ClassVar[str] = "mv_intersects({field}, [{list}])"

    # ECS fields declared normalize:array, restricted to those a detection rule
    # plausibly matches on. Over-inclusion is safe -- MV_INTERSECTS is correct on a
    # single-valued column too -- so a missing entry costs more than a spare one.
    # event.action is not ECS-normalized as an array but Elastic Defend emits one.
    # Extended, not replaced, by the multivalue_fields state key and constructor option.
    default_multivalue_fields: ClassVar[Tuple[str, ...]] = (
        "event.category",
        "event.type",
        "event.action",
        "tags",
        "process.args",
        "process.parent.args",
        "process.env_vars",
        "related.hash",
        "related.hosts",
        "related.ip",
        "related.user",
        "dns.answers",
        "dns.header_flags",
        "dns.resolved_ip",
        "host.ip",
        "host.mac",
        "registry.data.strings",
        "file.attributes",
        "user.roles",
        # Multivalued on every document carrying it, so a scalar match returns null
        # and the 4673/4674/4704 privilege-use rules could never fire.
        "winlog.event_data.PrivilegeList",
    )

    @staticmethod
    def _merge_state_list(
        declared: Iterable[str], key: str, state: ConversionState
    ) -> List[str]:
        """Field globs from the constructor, extended by the pipeline state key."""
        fields = list(declared)
        from_state = state.processing_state.get(key) if state else None
        if isinstance(from_state, str):
            from_state = [from_state]
        for f in from_state or ():
            if f not in fields:
                fields.append(f)
        return fields

    def _declared_multivalue_fields(self, state: ConversionState) -> List[str]:
        return self._merge_state_list(
            list(self.default_multivalue_fields) + list(self.multivalue_fields),
            "multivalue_fields",
            state,
        )

    def is_multivalue_field(self, field: str, state: ConversionState) -> bool:
        if not field:
            return False
        for pattern in self._declared_multivalue_fields(state):
            if field == pattern or fnmatch.fnmatchcase(field, pattern):
                return True
        return False

    def _mv_match(
        self, field: str, values: List[str], state: Optional[ConversionState] = None
    ) -> str:
        return self.mv_match_expression.format(
            field=self._ci_field(field, state),
            list=self.list_separator.join(self._ci_value(v) for v in values),
        )

    # Sigma |re is PCRE (unanchored substring); ES|QL RLIKE is Lucene regexp and
    # must match the whole value, so an unanchored pattern matches nothing. EQL has
    # the same bug. Leading ^ / trailing $ are consumed, being redundant once anchored.

    re_anchor_unanchored_patterns: ClassVar[bool] = True

    def _has_top_level_alternation(self, pattern: str) -> bool:
        depth = 0
        i = 0
        in_class = False
        while i < len(pattern):
            c = pattern[i]
            if c == "\\":
                i += 2
                continue
            if in_class:
                if c == "]":
                    in_class = False
            elif c == "[":
                in_class = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "|" and depth == 0:
                return True
            i += 1
        return False

    def anchor_regex(self, pattern: str) -> str:
        if not self.re_anchor_unanchored_patterns:
            return pattern
        starts = pattern.startswith("^")
        ends = pattern.endswith("$") and not pattern.endswith("\\$")
        body = pattern[1:] if starts else pattern
        if ends:
            body = body[:-1]
        # `.*` binds tighter than `|`: unwrapped, `.*foo|bar.*` parses as
        # `(.*foo)|(bar.*)`, which changes the meaning.
        if self._has_top_level_alternation(body):
            body = self.group_expression.format(expr=body)
        return ("" if starts else ".*") + body + ("" if ends else ".*")

    # A field-less Sigma keyword means "appears anywhere"; ES|QL has no such operator.
    # QSTR() searches default_field (`*`); the payload is a regexp, not a wildcard
    # term, which cannot hold punctuation or fold case. See KNOWN_ISSUES.md.

    unbound_search_expression: ClassVar[str] = "qstr({value})"

    # Operators are escaped too: they are enabled by default (RegExp.ALL).
    @property
    def lucene_regex_reserved(self) -> str:
        """Every character that must be escaped when embedding literal text."""
        return (
            self.lucene_regex_metacharacters
            + self.lucene_regex_operators
            + '"'  # delimits the ES|QL string literal
            + "/"  # delimits the regexp inside query_string
        )

    def escape_lucene_regex_literal(self, text: str) -> str:
        """Escape literal text for use inside a Lucene regexp."""
        return "".join(
            "\\" + ch if ch in self.lucene_regex_reserved else ch for ch in text
        )

    def _case_fold_regex_literal(self, text: str) -> str:
        """Fold already-escaped literal text to a case-insensitive Lucene regexp.

        Walks the escapes so a backslash is never separated from the character it
        protects, and folds each character through the same helper the PCRE
        translator uses -- there is one definition of "fold" for this dialect.
        """
        out = []
        escaped = False
        for ch in text:
            if escaped:
                out.append(ch)
                escaped = False
            elif ch == "\\":
                out.append(ch)
                escaped = True
            else:
                out.append(self._fold_regex_char(ch, False))
        return "".join(out)

    def unbound_regex_body(self, s: SigmaString) -> str:
        """Sigma keyword value -> Lucene regexp body, wildcards mapped, case folded."""
        parts = []
        for part in s.s:
            if part is SpecialChars.WILDCARD_MULTI:
                parts.append(".*")
            elif part is SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
            else:
                literal = self.escape_lucene_regex_literal(str(part))
                if self.case_insensitive:
                    literal = self._case_fold_regex_literal(literal)
                parts.append(literal)
        return "".join(parts)

    # A Lucene regexp matches per analyzed TOKEN, so on a `text` field it never
    # matches a value with spaces or punctuation. A phrase is the mirror image, so
    # both arms are emitted and OR-ed to cover either mapping.
    unbound_search_phrase_expression: ClassVar[str] = "qstr({value})"
    emit_unbound_phrase_arm: ClassVar[bool] = True

    def _esql_literal(self, text: str) -> str:
        """Escape as an ES|QL string literal: backslashes first, then quotes."""
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def render_unbound_search(self, body: str, phrase: Optional[str] = None) -> str:
        """Wrap a regexp body -- and optionally a phrase -- as QSTR calls.

        Two layers, applied once each and in this order: the pattern is anchored
        with `.*` for Sigma's substring semantics and delimited with `/`, then the
        whole thing is escaped as an ES|QL string literal.  Getting this order
        wrong is what broke LIKE and RLIKE upstream.
        """
        regex_arm = self.unbound_search_expression.format(
            value=self._esql_literal(f"/.*{body}.*/")
        )
        if not (self.emit_unbound_phrase_arm and phrase):
            return regex_arm
        # query_string phrase syntax: the value is quoted, and a literal quote or
        # backslash inside it is backslash-escaped before the ES|QL layer runs.
        inner = phrase.replace("\\", "\\\\").replace('"', '\\"')
        phrase_arm = self.unbound_search_phrase_expression.format(
            value=self._esql_literal(f'"{inner}"')
        )
        return self.group_expression.format(
            expr=regex_arm
            + self.token_separator
            + self.or_token
            + self.token_separator
            + phrase_arm
        )

    def unbound_phrase_text(self, s: SigmaString) -> Optional[str]:
        """The literal text of a keyword value, or None if no phrase arm is needed.

        A wildcard value cannot be a phrase at all, and a single alphanumeric
        token is already matched by the regexp arm on an analyzed field, so
        emitting one costs a second full-text clause for nothing.
        """
        parts = []
        for part in s.s:
            if part in (SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE):
                return None
            parts.append(str(part))
        text = "".join(parts)
        if not text or text.isalnum():
            return None
        return text

    def convert_condition_val_str(self, cond, state) -> str:
        return self.render_unbound_search(
            self.unbound_regex_body(cond.value),
            self.unbound_phrase_text(cond.value),
        )

    def convert_condition_val_num(self, cond, state) -> str:
        # Same phrase-arm rule as the string path: a bare number is one token,
        # so the regexp arm already covers analyzed fields.
        text = str(cond.value)
        return self.render_unbound_search(
            self.escape_lucene_regex_literal(text),
            None if text.isalnum() else text,
        )

    def convert_condition_val_re(self, cond, state) -> str:
        # An unbound |re is already a regexp; it needs the same anchoring every
        # other RLIKE pattern gets, but no wildcard mapping and no case folding.
        regex_text = cond.value.escape(
            (), self.re_escape_char, False, self.re_flag_prefix
        )
        return self.render_unbound_search(regex_text.replace("/", "\\/"))

    # Sigma treats all values as case-insensitive; EQL's `:` honours that, ES|QL's
    # ==/LIKE/starts_with/ends_with do not. ES|QL has no =~ and Lucene regexp rejects
    # inline (?i), so TO_LOWER is the only mechanism. Off by default: semantic change,
    # unmeasured above lab index sizes. .caseless fields are already normalised.

    case_insensitive_expression: ClassVar[str] = "to_lower({field})"
    case_insensitive_exempt_suffixes: ClassVar[Tuple[str, ...]] = (".caseless",)

    # One map, three consumers: TO_LOWER rejects non-strings, numeric literals must
    # lose their quotes, and string operators need TO_STRING -- so they cannot
    # disagree. A real string field listed here silently restores case sensitivity.

    default_field_types: ClassVar[Dict[str, str]] = {
        "*.ip": "ip",
        "dns.resolved_ip": "ip",
        "*code_signature.exists": "boolean",
        "*code_signature.trusted": "boolean",
        "*code_signature.valid": "boolean",
        "host.containerized": "boolean",
        "*.snapshot": "boolean",
        "*.pid": "numeric",
        "*.port": "numeric",
        "*.args_count": "numeric",
        "*.packets": "numeric",
        "file.size": "numeric",
        "event.sequence": "numeric",
        "event.severity": "numeric",
        "@timestamp": "date",
        "event.ingested": "date",
        "event.created": "date",
        "file.created": "date",
        "file.mtime": "date",
        "file.ctime": "date",
        "file.accessed": "date",
    }

    to_string_expression: ClassVar[str] = "to_string({field})"

    def field_type(
        self, field: str, state: Optional[ConversionState] = None
    ) -> Optional[str]:
        """The declared type of a field, or None if it is a string."""
        if not field:
            return None
        declared = dict(self.default_field_types)
        from_state = state.processing_state.get("field_types") if state else None
        if isinstance(from_state, dict):
            declared.update(from_state)
        for pattern, kind in declared.items():
            if field == pattern or fnmatch.fnmatchcase(field, pattern):
                return kind
        return None

    @staticmethod
    def _literal_matches_type(text: str, kind: str) -> bool:
        """Can ES|QL compare this literal to that field type natively?"""
        if kind == "numeric":
            if "_" in text:
                return False  # float() accepts 1_000; ES|QL does not
            try:
                return math.isfinite(float(text))  # nan/inf are parse errors
            except ValueError:
                return False
        if kind == "boolean":
            return text.lower() in ("true", "false")
        if kind == "ip":
            # ES|QL coerces an address literal to `ip` and pushes it down; only a
            # non-address (`'-'`, or a wildcard) needs TO_STRING.
            try:
                ipaddress.ip_network(text, strict=False)
                return True
            except ValueError:
                return False
        return False

    def _typed_field(self, field: str, state: Optional[ConversionState] = None) -> str:
        """Wrap a non-string field so string operators accept it."""
        quoted = self.escape_and_quote_field(field)
        if self.field_type(field, state) is None:
            return quoted
        return self.to_string_expression.format(field=quoted)

    # Skipped for non-string fields and `.caseless` subfields, which a normalizer
    # has already folded. The constructor option and state key are the escape hatch.
    def _declared_ci_exempt_fields(self, state: ConversionState) -> List[str]:
        return self._merge_state_list(
            self.case_insensitive_exempt_fields, "case_insensitive_exempt_fields", state
        )

    def is_ci_exempt_field(self, field: str, state: ConversionState) -> bool:
        if not field:
            return False
        if any(field.endswith(sfx) for sfx in self.case_insensitive_exempt_suffixes):
            return True
        if self.field_type(field, state) is not None:
            return True
        for pattern in self._declared_ci_exempt_fields(state):
            if field == pattern or fnmatch.fnmatchcase(field, pattern):
                return True
        return False

    def _ci_field(self, field: str, state: Optional[ConversionState] = None) -> str:
        quoted = self.escape_and_quote_field(field)
        if not self.case_insensitive:
            return quoted
        if self.is_ci_exempt_field(field, state):
            return quoted
        return self.case_insensitive_expression.format(field=quoted)

    def _ci_value(self, rendered: str) -> str:
        return rendered.lower() if self.case_insensitive else rendered

    # No MV_LIKE until ES 9.6, and LIKE/starts_with/ends_with return null on an
    # array. Joining with a separator that cannot occur in data, padded both ends,
    # turns a per-element match into one LIKE:
    #   ["conn","notice"] -> \x01conn\x01notice\x01
    #   element == X -> "*<SEP>X<SEP>*"   startswith -> "*<SEP>X*"
    #   endswith  -> "*X<SEP>*"           contains   -> "*X*"
    # Exact equality still uses MV_INTERSECTS, which stays pushdown-friendly.

    mv_join_separator: ClassVar[str] = "\x01"
    mv_join_expression: ClassVar[str] = (
        'concat("{sep}", mv_concat({field}, "{sep}"), "{sep}")'
    )

    def _mv_joined_field(
        self, field: str, state: Optional[ConversionState] = None
    ) -> str:
        return self.mv_join_expression.format(
            sep=self.mv_join_separator,
            field=self._ci_field(field, state),
        )

    def _mv_like_pattern(self, s: SigmaString, state: ConversionState) -> str:
        """LIKE pattern against the padded join: anchor whichever end is closed."""
        literal = self._ci_value(self.convert_value_like(s, state))
        body = literal[1:-1]  # strip the surrounding quotes
        sep = self.mv_join_separator
        if not s.startswith(SpecialChars.WILDCARD_MULTI):
            body = "*" + sep + body
        if not s.endswith(SpecialChars.WILDCARD_MULTI):
            body = body + sep + "*"
        return '"' + body + '"'

    def build_from_clause(
        self, rule: SigmaRule, query: str, state: ConversionState
    ) -> str:
        """Assemble the source, metadata and optional projection around a where clause.

        FROM without a projection returns one column per field mapped across every
        index the pattern matched, so the `keep` state exists to narrow that. It is
        applied only to plain rules: a correlation appends STATS after this point,
        and metadata columns do not survive an aggregation.
        """
        metadata = state.processing_state.get(
            "metadata", self.state_defaults["metadata"]
        )
        index_state = state.processing_state.get("index", self.state_defaults["index"])
        keep = state.processing_state.get("keep", self.state_defaults["keep"])

        full_query = f"from {index_state} metadata {metadata} | where {query}"
        if keep and isinstance(rule, SigmaRule):
            full_query += f" | keep {keep}"
        return full_query

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """Finalize query for default output format by adding the FROM clause."""
        return self.build_from_clause(rule, query, state)

    def finalize_query_kibana_ndjson(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        full_query = self.build_from_clause(rule, query, state)

        return {
            "attributes": {
                "columns": [],
                "description": (
                    rule.description
                    if rule.description is not None
                    else "No description"
                ),
                "grid": {},
                "hideChart": False,
                "isTextBasedQuery": True,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": str(
                        json.dumps(
                            {
                                "query": {"esql": full_query},
                                "index": {
                                    "title": state.processing_state["index"],
                                    "timeFieldName": "@timestamp",
                                    "sourceFilters": [],
                                    "type": "esql",
                                    "fieldFormats": {},
                                    "runtimeFieldMap": {},
                                    "allowNoIndex": False,
                                    "name": state.processing_state["index"],
                                    "allowHidden": False,
                                },
                                "filter": [],
                            }
                        )
                    ),
                },
                "sort": [["@timestamp", "desc"]],
                "timeRestore": False,
                "title": f"SIGMA - {rule.title}",
                "usesAdHocDataView": False,
            },
            "id": str(rule.id),
            "managed": False,
            "references": [],
            "type": "search",
            "typeMigrationVersion": "10.2.0",
        }

    def finalize_output_kibana_ndjson(self, queries: List[Dict]) -> List[List[Dict]]:
        return list(queries)

    def finalize_output_threat_model(self, tags: List[SigmaRuleTag]) -> Iterable[Dict]:
        from sigma.data.mitre_attack import (
            mitre_attack_tactics,
            mitre_attack_techniques,
        )

        attack_tags = [t for t in tags if t.namespace == "attack"]
        if not len(attack_tags) >= 2:
            return []

        techniques = [
            tag.name.upper() for tag in attack_tags if re.match(r"[tT]\d{4}", tag.name)
        ]
        tactics = [
            tag.name.lower()
            for tag in attack_tags
            if not re.match(r"[tT]\d{4}", tag.name)
        ]

        for tactic, technique in zip(tactics, techniques):
            if (
                not tactic or not technique
            ):  # Only add threat if tactic and technique is known
                continue

            try:
                if "." in technique:  # Contains reference to Mitre Att&ck subtechnique
                    sub_technique = technique
                    technique = technique[0:5]
                    sub_technique_name = mitre_attack_techniques[sub_technique]

                    sub_techniques = [
                        {
                            "id": sub_technique,
                            "reference": f"https://attack.mitre.org/techniques/{sub_technique.replace('.', '/')}",
                            "name": sub_technique_name,
                        }
                    ]
                else:
                    sub_techniques = []

                tactic_id = [
                    id
                    for (id, name) in mitre_attack_tactics.items()
                    if name == tactic.replace("_", "-")
                ][0]
                technique_name = mitre_attack_techniques[technique]
            except (IndexError, KeyError):
                # Occurs when Sigma Mitre Att&ck list is out of date
                continue

            yield {
                "tactic": {
                    "id": tactic_id,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}",
                    "name": tactic.title().replace("_", " "),
                },
                "framework": "MITRE ATT&CK",
                "technique": [
                    {
                        "id": technique,
                        "reference": f"https://attack.mitre.org/techniques/{technique}",
                        "name": technique_name,
                        "subtechnique": sub_techniques,
                    }
                ],
            }

        for tag in attack_tags:
            tags.remove(tag)

    def finalize_query_siem_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Create SIEM Rules in JSON Format. These rules could be imported into Kibana using the
        Create Rule API https://www.elastic.co/guide/en/kibana/current/create-rule-api.html
        This API (and generated data) is NOT the same like importing Detection Rules via:
        Kibana -> Security -> Alerts -> Manage Rules -> Import
        If you want to have a nice importable NDJSON File for the Security Rule importer
        use pySigma Format 'siem_rule_ndjson' instead.
        """
        full_query = self.build_from_clause(rule, query, state)

        return {
            "name": f"SIGMA - {rule.title}",
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "enabled": True,
            "consumer": "siem",
            "throttle": None,
            "schedule": {
                "interval": f"{self.schedule_interval}{self.schedule_interval_unit}"
            },
            "params": {
                "author": [rule.author] if rule.author is not None else [],
                "description": (
                    rule.description
                    if rule.description is not None
                    else "No description"
                ),
                "ruleId": str(rule.id),
                "falsePositives": rule.falsepositives,
                "from": f"now-{self.schedule_interval}{self.schedule_interval_unit}",
                "immutable": False,
                "license": (rule.license if rule.license is not None else "DRL"),
                "outputIndex": "",
                "meta": {
                    "from": "1m",
                },
                "maxSignals": 100,
                "relatedIntegrations": [],
                "requiredFields": [],
                "riskScore": (
                    self.severity_risk_mapping[rule.level.name]
                    if rule.level is not None
                    else 21
                ),
                "riskScoreMapping": [],
                "setup": "",
                "severity": (
                    str(rule.level.name).lower() if rule.level is not None else "low"
                ),
                "severityMapping": [],
                "threat": list(self.finalize_output_threat_model(rule.tags)),
                "to": "now",
                "references": rule.references,
                "version": 1,
                "exceptionsList": [],
                "type": "esql",
                "language": "esql",
                "query": full_query,
            },
            "rule_type_id": "siem.esqlRule",
            "notify_when": "onActiveAlert",
            "actions": [],
        }

    def finalize_output_siem_rule(self, queries: List[Dict]) -> List[List[Dict]]:
        return list(queries)

    def finalize_query_siem_rule_ndjson(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Generating SIEM/Detection Rules in NDJSON Format. Compatible with

        https://www.elastic.co/guide/en/security/current/rules-ui-management.html#import-export-rules-ui
        """
        full_query = self.build_from_clause(rule, query, state)

        return {
            "id": str(rule.id),
            "name": f"SIGMA - {rule.title}",
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "interval": f"{self.schedule_interval}{self.schedule_interval_unit}",
            "enabled": True,
            "description": (
                rule.description if rule.description is not None else "No description"
            ),
            "risk_score": (
                0
                if rule.level is not None
                and str(rule.level.name).lower() == "informational"
                else (
                    self.severity_risk_mapping[rule.level.name]
                    if rule.level is not None
                    else 21
                )
            ),
            "severity": (
                "low"
                if rule.level is None or str(rule.level.name).lower() == "informational"
                else str(rule.level.name).lower()
            ),
            "note": "",
            "license": (rule.license if rule.license is not None else "DRL"),
            "output_index": "",
            "meta": {
                "from": "1m",
            },
            "author": [rule.author] if rule.author is not None else [],
            "false_positives": rule.falsepositives,
            "from": f"now-{self.schedule_interval}{self.schedule_interval_unit}",
            "rule_id": str(rule.id),
            "max_signals": 100,
            "risk_score_mapping": [],
            "severity_mapping": [],
            "threat": list(self.finalize_output_threat_model(rule.tags)),
            "to": "now",
            "references": rule.references,
            "version": 1,
            "exceptions_list": [],
            "immutable": False,
            "related_integrations": [],
            "required_fields": [],
            "setup": "",
            "type": "esql",
            "language": "esql",
            "query": full_query,
            "actions": [],
        }

    def finalize_output_siem_rule_ndjson(self, queries: List[Dict]) -> List[List[Dict]]:
        return list(queries)
