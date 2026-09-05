package cdk_preflight

import rego.v1

_pf_waftt_url := "https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-preparse-transformation.html"

_pf_waftt_fix := "Give each TextTransformations / PreParseTextTransformations entry a distinct Priority (at most 10 entries), and use PreParseTextTransformations only with SingleQueryArgument / AllQueryArguments and the pre-parse types NONE, URL_DECODE, URL_DECODE_UNI, COMBINE_DUPLICATE_QUERY_ARGS_BY_COMMA, REPLACE_SEMICOLONS_WITH_AMPERSANDS"

# every transformation list: [container, path, list]
_pf_waftt contains [name, sprintf("%s.%s", [_pf_waflib_path(i, array.concat(p, [kind])), f]), l] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	some f in {"TextTransformations", "PreParseTextTransformations"}
	l := body[f]
	is_array(l)
}

_pf_waftt contains [name, sprintf("%s.CustomKeys[%d].%s.TextTransformations", [_pf_waflib_path(i, array.concat(p, ["RateBasedStatement"])), k, kk]), l] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "RateBasedStatement"
	some k
	some kk in {"Header", "Cookie", "QueryArgument", "QueryString", "UriPath"}
	l := body.CustomKeys[k][kk].TextTransformations
	is_array(l)
}

violation contains make_diag_full("pf-wafv2-text-transformations", "ERROR", name, sprintf("%s[%d].Priority", [pp, m]),
	sprintf("priority %d is also used by entry [%d]; the create call fails with \"You have a duplicate priority. Priorities must be unique.\"", [pr, k]),
	_pf_waftt_fix, _pf_waftt_url) if {
	some [name, pp, l] in _pf_waftt
	some k, m
	k < m
	pr := l[k].Priority
	is_number(pr)
	l[m].Priority == pr
}

violation contains make_diag_full("pf-wafv2-text-transformations", "ERROR", name, pp,
	sprintf("%d transformations; at most 10 per statement (the create call fails with WAFLimitsExceededException)", [count(l)]),
	_pf_waftt_fix, _pf_waftt_url) if {
	some [name, pp, l] in _pf_waftt
	count(l) > 10
}

_pf_waftt_pre contains [name, pp, body, l] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	l := body.PreParseTextTransformations
	is_array(l)
	pp := sprintf("%s.PreParseTextTransformations", [_pf_waflib_path(i, array.concat(p, [kind]))])
}

violation contains make_diag_full("pf-wafv2-text-transformations", "ERROR", name, pp,
	sprintf("pre-parse transformations only apply to SingleQueryArgument / AllQueryArguments, not %s; the create call fails with \"PreParseTextTransformations is only supported for SingleQueryArgument and AllQueryArguments field to match types.\"", [comps]),
	_pf_waftt_fix, _pf_waftt_url) if {
	some [name, pp, body, l] in _pf_waftt_pre
	f := body.FieldToMatch
	is_object(f)
	some k in object.keys(f)
	not k in {"SingleQueryArgument", "AllQueryArguments"}
	comps := concat(", ", [kk | some kk in object.keys(f)])
}

_pf_waftt_pre_types := {"NONE", "URL_DECODE", "URL_DECODE_UNI", "COMBINE_DUPLICATE_QUERY_ARGS_BY_COMMA", "REPLACE_SEMICOLONS_WITH_AMPERSANDS"}

violation contains make_diag_full("pf-wafv2-text-transformations", "ERROR", name, sprintf("%s[%d].Type", [pp, k]),
	sprintf("'%s' is not a pre-parse transformation type; the CloudFormation handler fails with \"No enum constant software.amazon.awssdk.services.wafv2.model.PreParseTextTransformationType.%s\"", [t, t]),
	_pf_waftt_fix, _pf_waftt_url) if {
	some [name, pp, body, l] in _pf_waftt_pre
	some k
	t := l[k].Type
	is_string(t)
	not t in _pf_waftt_pre_types
}
