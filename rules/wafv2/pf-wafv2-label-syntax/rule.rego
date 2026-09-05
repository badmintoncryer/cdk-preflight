package cdk_preflight

import rego.v1

_pf_waflab_url := "https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-label-requirements.html"

_pf_waflab_fix := "Use colon-separated components without aws / awswaf / waf / managed / rulegroup / webacl / regexpatternset / ipset, no leading, trailing or doubled colons, at most 8 components of up to 128 characters, no duplicates, and no RuleLabels on managed rule group / rule group reference rules; a NAMESPACE match key ends with a colon and a LABEL key does not"

_pf_waflab_reserved := {"aws", "awswaf", "waf", "managed", "rulegroup", "webacl", "regexpatternset", "ipset"}

_pf_waflab contains [name, i, k, lbl, comps] if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i, k
	lbl := rules[i].RuleLabels[k].Name
	is_string(lbl)
	comps := split(lbl, ":")
}

_pf_waflab_path(i, k) := sprintf("Properties.Rules[%d].RuleLabels[%d].Name", [i, k])

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, _pf_waflab_path(i, k),
	sprintf("label '%s' uses the reserved word '%s'; the create call fails with \"The parameter value isn't supported.\"", [lbl, c]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, i, k, lbl, comps] in _pf_waflab
	some c in comps
	c in _pf_waflab_reserved
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, _pf_waflab_path(i, k),
	sprintf("label '%s' has an empty component (leading, trailing or doubled colon); the create call fails with \"The parameter value is out of bounds.\"", [lbl]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, i, k, lbl, comps] in _pf_waflab
	some c in comps
	c == ""
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, _pf_waflab_path(i, k),
	sprintf("label '%s' has %d components; at most 8 (7 namespaces and a name) are accepted, the create call fails with \"The parameter value is out of bounds.\"", [lbl, count(comps)]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, i, k, lbl, comps] in _pf_waflab
	count(comps) > 8
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, _pf_waflab_path(i, k),
	sprintf("label component '%s' is %d characters; each component is limited to 128 (the create call fails with \"The parameter value is out of bounds.\")", [c, count(c)]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, i, k, lbl, comps] in _pf_waflab
	some c in comps
	count(c) > 128
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, _pf_waflab_path(i, m),
	sprintf("label '%s' is already listed at RuleLabels[%d]; the create call fails with \"You have duplicated some of the information in the parameter.\"", [lbl, k]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, i, k, lbl, comps] in _pf_waflab
	some [nm, ii, m, lbl2, comps2] in _pf_waflab
	nm == name
	ii == i
	lbl2 == lbl
	k < m
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, sprintf("Properties.Rules[%d].RuleLabels", [i]),
	sprintf("a %s rule cannot add labels; the create call fails with \"The parameter value isn't supported.\"", [kind]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, i, kind] in _pf_waflib_tops
	kind in {"ManagedRuleGroupStatement", "RuleGroupReferenceStatement"}
	rules := _pf_waflib_rules(name)
	lbls := rules[i].RuleLabels
	is_array(lbls)
	count(lbls) > 0
}

# LabelMatchStatement keys
_pf_waflab_lm contains [name, pp, scope, key] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "LabelMatchStatement"
	pp := sprintf("%s.Key", [_pf_waflib_path(i, array.concat(p, ["LabelMatchStatement"]))])
	scope := body.Scope
	key := body.Key
	is_string(key)
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, pp,
	sprintf("NAMESPACE match key '%s' must end with a colon; the create call fails with \"The parameter value isn't supported.\"", [key]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, pp, scope, key] in _pf_waflab_lm
	scope == "NAMESPACE"
	not endswith(key, ":")
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, pp,
	sprintf("LABEL match key '%s' must end with the label name, not a colon; the create call fails with \"The parameter value isn't supported.\"", [key]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, pp, scope, key] in _pf_waflab_lm
	scope == "LABEL"
	endswith(key, ":")
}

violation contains make_diag_full("pf-wafv2-label-syntax", "ERROR", name, pp,
	sprintf("match key '%s' has an empty component; the create call fails with \"The parameter value is out of bounds.\"", [key]),
	_pf_waflab_fix, _pf_waflab_url) if {
	some [name, pp, scope, key] in _pf_waflab_lm
	parts := split(key, ":")
	some j
	parts[j] == ""
	not _pf_waflab_trailing(scope, parts, j)
}

_pf_waflab_trailing(scope, parts, j) if {
	scope == "NAMESPACE"
	j == count(parts) - 1
}
