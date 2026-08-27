from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression, SigmaString, SpecialChars, SigmaRegularExpression
import sigma
import re
import json
import fnmatch
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
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.schedule_interval = schedule_interval
        self.schedule_interval_unit = schedule_interval_unit
        # Fields known to hold several values per document.  Unioned with the
        # pipeline state key of the same name; entries may be globs.
        self.multivalue_fields = list(multivalue_fields or [])
        self.case_insensitive = case_insensitive
        self._mv_unsupported = []
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
            if ch in (self.like_escape_char, self.like_wildcard_multi, self.like_wildcard_single):
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
            and (self.startswith_expression_allow_special or not v[:-1].contains_special())
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
            and (self.contains_expression_allow_special or not v[1:-1].contains_special())
        ):
            return False
        return self.wildcard_match_expression is not None

    def convert_condition_field_eq_val_str(self, cond, state):
        v = cond.value
        if isinstance(v, SigmaString) and self._selects_wildcard_match(v):
            if self.is_multivalue_field(cond.field, state):
                return self.wildcard_match_expression.format(
                    field=self._mv_joined_field(cond.field),
                    value=self._mv_like_pattern(v, state),
                    backend=self,
                )
            return self.wildcard_match_expression.format(
                field=self._ci_field(cond.field),
                value=self._ci_value(self.convert_value_like(v, state)),
                backend=self,
            )
        if isinstance(v, SigmaString) and self.is_multivalue_field(cond.field, state):
            if v.contains_special():
                # startswith / endswith against a multivalued field
                return self.wildcard_match_expression.format(
                    field=self._mv_joined_field(cond.field),
                    value=self._mv_like_pattern(v, state),
                    backend=self,
                )
            return self._mv_match(cond.field, [self.convert_value_str(v, state)])
        if self.case_insensitive and isinstance(v, SigmaString):
            # startswith/endswith/eq all take the field as first operand
            return self._convert_eq_val_str_ci(cond, state)
        return super().convert_condition_field_eq_val_str(cond, state)

    def _convert_eq_val_str_ci(self, cond, state):
        v = cond.value
        field = self._ci_field(cond.field)
        if (self.startswith_expression is not None and v.endswith(SpecialChars.WILDCARD_MULTI)
                and not v[:-1].contains_special()):
            return self.startswith_expression.format(
                field=field, value=self._ci_value(self.convert_value_str(v[:-1], state)), backend=self)
        if (self.endswith_expression is not None and v.startswith(SpecialChars.WILDCARD_MULTI)
                and not v[1:].contains_special()):
            return self.endswith_expression.format(
                field=field, value=self._ci_value(self.convert_value_str(v[1:], state)), backend=self)
        return self.eq_expression.format(
            field=field, value=self._ci_value(self.convert_value_str(v, state)), backend=self)

    def convert_condition_as_in_expression(self, cond, state):
        args = getattr(cond, "args", [])
        field = getattr(args[0], "field", None) if args else None
        if field and self.is_multivalue_field(field, state) and isinstance(cond, ConditionOR):
            vals = []
            for arg in args:
                val = arg.value
                if not isinstance(val, SigmaString):
                    return super().convert_condition_as_in_expression(cond, state)
                vals.append(self.convert_value_str(val, state))
            return self._mv_match(field, vals)
        return super().convert_condition_as_in_expression(cond, state)

    # Same two layers as LIKE, in the wrong order upstream: the quote escape is
    # added after the escape char is doubled, so its own backslash never is.
    # Order here is regex layer, then string literal.

    re_escape: ClassVar[Tuple[str, ...]] = ()  # handled in convert_value_re instead
    re_escape_escape_char: bool = False

    def convert_value_re(self, r: SigmaRegularExpression, state: ConversionState) -> str:
        regex_text = r.escape((), self.re_escape_char, False, self.re_flag_prefix)
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
        "event.category", "event.type", "event.action", "tags",
        "process.args", "process.parent.args", "process.env_vars",
        "related.hash", "related.hosts", "related.ip", "related.user",
        "dns.answers", "dns.header_flags", "dns.resolved_ip",
        "host.ip", "host.mac",
        "registry.data.strings", "file.attributes", "user.roles",
    )

    def _declared_multivalue_fields(self, state: ConversionState) -> List[str]:
        fields = list(self.default_multivalue_fields) + list(self.multivalue_fields)
        from_state = state.processing_state.get("multivalue_fields") if state else None
        if isinstance(from_state, str):
            from_state = [from_state]
        if from_state:
            for f in from_state:
                if f not in fields:
                    fields.append(f)
        return fields

    def is_multivalue_field(self, field: str, state: ConversionState) -> bool:
        if not field:
            return False
        for pattern in self._declared_multivalue_fields(state):
            if field == pattern or fnmatch.fnmatchcase(field, pattern):
                return True
        return False

    def mv_unsupported_matches(self) -> List[str]:
        """Wildcard/regex matches emitted against a declared multivalued field.

        These cannot be made MV-safe with the functions ES|QL provides today and
        are silent misses.  Collected during conversion for reporting."""
        return list(self._mv_unsupported)

    def _mv_match(self, field: str, values: List[str]) -> str:
        return self.mv_match_expression.format(
            field=self._ci_field(field),
            list=self.list_separator.join(self._ci_value(v) for v in values),
        )

    # Sigma |re is PCRE (unanchored substring); ES|QL RLIKE is Lucene regexp and
    # must match the whole value, so an unanchored pattern matches nothing. EQL has
    # the same bug. Leading ^ / trailing $ are consumed, being redundant once anchored.

    re_anchor_unanchored_patterns: ClassVar[bool] = True

    def anchor_regex(self, pattern: str) -> str:
        if not self.re_anchor_unanchored_patterns:
            return pattern
        starts = pattern.startswith("^")
        ends = pattern.endswith("$") and not pattern.endswith("\\$")
        body = pattern[1:] if starts else pattern
        if ends:
            body = body[:-1]
        return ("" if starts else ".*") + body + ("" if ends else ".*")

    # Sigma treats all values as case-insensitive; EQL's `:` honours that, ES|QL's
    # ==/LIKE/starts_with/ends_with do not. ES|QL has no =~ and Lucene regexp rejects
    # inline (?i), so TO_LOWER is the only mechanism. Off by default: semantic change,
    # unmeasured above lab index sizes. .caseless fields are already normalised.

    case_insensitive_expression: ClassVar[str] = "to_lower({field})"
    case_insensitive_exempt_suffixes: ClassVar[Tuple[str, ...]] = (".caseless",)

    def _ci_field(self, field: str) -> str:
        quoted = self.escape_and_quote_field(field)
        if not self.case_insensitive:
            return quoted
        if any(field.endswith(sfx) for sfx in self.case_insensitive_exempt_suffixes):
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
    mv_join_expression: ClassVar[str] = 'concat("{sep}", mv_concat({field}, "{sep}"), "{sep}")'

    def _mv_joined_field(self, field: str) -> str:
        return self.mv_join_expression.format(
            sep=self.mv_join_separator,
            field=self._ci_field(field),
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

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """Finalize query for default output format by adding the FROM clause."""
        # Get metadata from processing state
        metadata = state.processing_state.get("metadata", self.state_defaults["metadata"])
        index_state = state.processing_state.get("index", self.state_defaults["index"])
        
        # Add the 'from' clause to the query
        return f"from {index_state} metadata {metadata} | where {query}"

    def finalize_query_kibana_ndjson(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        # Get metadata from processing state
        metadata = state.processing_state.get("metadata", self.state_defaults["metadata"])
        index_state = state.processing_state.get("index", self.state_defaults["index"])
        
        # Add the 'from' clause to the query
        full_query = f"from {index_state} metadata {metadata} | where {query}"
        
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
        from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques
        
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
        # Get metadata from processing state
        metadata = state.processing_state.get("metadata", self.state_defaults["metadata"])
        index_state = state.processing_state.get("index", self.state_defaults["index"])
        
        # Add the 'from' clause to the query
        full_query = f"from {index_state} metadata {metadata} | where {query}"

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
                "license": (
                    rule.license 
                    if rule.license is not None 
                    else "DRL"
                ),
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
        # Get metadata from processing state
        metadata = state.processing_state.get("metadata", self.state_defaults["metadata"])
        index_state = state.processing_state.get("index", self.state_defaults["index"])
        
        # Add the 'from' clause to the query
        full_query = f"from {index_state} metadata {metadata} | where {query}"

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
            "license": (
                rule.license 
                if rule.license is not None 
                else "DRL"
            ),
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
