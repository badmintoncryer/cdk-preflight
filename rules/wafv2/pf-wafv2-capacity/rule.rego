package cdk_preflight

import rego.v1

_pf_wafcap_url := "https://docs.aws.amazon.com/waf/latest/developerguide/aws-waf-capacity-units.html"

_pf_wafcap_fix := "Raise Capacity to at least the WCUs the rules need (check with aws wafv2 check-capacity) within the 5,000 maximum, or simplify the rules (XSS 40, SQLi 20/30, regex pattern set 25, each transformation 10, managed rule groups their published capacity)"

violation contains make_diag_full("pf-wafv2-capacity", "ERROR", name, "Properties.Capacity",
	sprintf("Capacity %d is below the minimum of 1 (the schema allows 0, the create call fails with \"Invalid value for parameter Capacity, value: 0, valid min value: 1\")", [c]),
	_pf_wafcap_fix, _pf_wafcap_url) if {
	some name in resources_of_type("AWS::WAFv2::RuleGroup")
	c := resolve(name, "Properties.Capacity")
	is_number(c)
	c < 1
}

violation contains make_diag_full("pf-wafv2-capacity", "ERROR", name, "Properties.Capacity",
	sprintf("Capacity %d exceeds the 5,000 WCU maximum for a rule group (the create call fails with WAFLimitsExceededException NUM_CAPACITY_UNITS_IN_RULE_GROUP)", [c]),
	_pf_wafcap_fix, _pf_wafcap_url) if {
	some name in resources_of_type("AWS::WAFv2::RuleGroup")
	c := resolve(name, "Properties.Capacity")
	is_number(c)
	c > 5000
}

# ---- WCU estimate (docs table, calibrated against CheckCapacity 2026-09-05) ----
_pf_wafcap_base("GeoMatchStatement", b) := 1

_pf_wafcap_base("AsnMatchStatement", b) := 1

_pf_wafcap_base("LabelMatchStatement", b) := 1

_pf_wafcap_base("SizeConstraintStatement", b) := 1

_pf_wafcap_base("RegexMatchStatement", b) := 3

_pf_wafcap_base("RegexPatternSetReferenceStatement", b) := 25

_pf_wafcap_base("XssMatchStatement", b) := 40

_pf_wafcap_base("SqliMatchStatement", b) := 30 if b.SensitivityLevel == "HIGH"

_pf_wafcap_base("SqliMatchStatement", b) := 20 if object.get(b, "SensitivityLevel", "LOW") != "HIGH"

_pf_wafcap_base("ByteMatchStatement", b) := 2 if b.PositionalConstraint in {"EXACTLY", "STARTS_WITH", "ENDS_WITH"}

_pf_wafcap_base("ByteMatchStatement", b) := 10 if not b.PositionalConstraint in {"EXACTLY", "STARTS_WITH", "ENDS_WITH"}

_pf_wafcap_base("IPSetReferenceStatement", b) := 5 if b.IPSetForwardedIPConfig.Position == "ANY"

_pf_wafcap_base("IPSetReferenceStatement", b) := 1 if object.get(b, "IPSetForwardedIPConfig", {}) == {}

_pf_wafcap_base("IPSetReferenceStatement", b) := 1 if {
	object.get(b, "IPSetForwardedIPConfig", {}) != {}
	b.IPSetForwardedIPConfig.Position != "ANY"
}

_pf_wafcap_base("RateBasedStatement", b) := 2 + (30 * count(object.get(b, "CustomKeys", [])))

_pf_wafcap_base("ManagedRuleGroupStatement", b) := _pf_waflib_managed[b.Name] if b.VendorName == "AWS"

_pf_wafcap_base("ManagedRuleGroupStatement", b) := 0 if b.VendorName != "AWS"

_pf_wafcap_base("RuleGroupReferenceStatement", b) := c if {
	x := _pf_waflib_getatt(b.Arn)
	c := resolve(x, "Properties.Capacity")
	is_number(c)
}

_pf_wafcap_base("RuleGroupReferenceStatement", b) := 0 if not _pf_waflib_getatt(b.Arn)

_pf_wafcap_base("AndStatement", b) := 0

_pf_wafcap_base("OrStatement", b) := 0

_pf_wafcap_base("NotStatement", b) := 0

_pf_wafcap_json(kind, b) if {
	kind in _pf_waflib_match_keys
	b.FieldToMatch.JsonBody
}

_pf_wafcap_mult(kind, b) := 2 if _pf_wafcap_json(kind, b)

_pf_wafcap_mult(kind, b) := 1 if not _pf_wafcap_json(kind, b)

_pf_wafcap_allq(kind, b) := 10 if {
	kind in _pf_waflib_match_keys
	b.FieldToMatch.AllQueryArguments
}

_pf_wafcap_allq(kind, b) := 0 if not b.FieldToMatch.AllQueryArguments

_pf_wafcap_leaf contains [name, i, p, kind, c] if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	c := (_pf_wafcap_base(kind, b) * _pf_wafcap_mult(kind, b)) + _pf_wafcap_allq(kind, b)
}

# AWS charges a transformation once per (component, type) across the container
_pf_wafcap_tt contains [name, fj, t] if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	some k
	t := b.TextTransformations[k].Type
	t != "NONE"
	fj := json.marshal(b.FieldToMatch)
}

_pf_wafcap_pre contains [name, i, p, kind, k] if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	some k
	t := b.PreParseTextTransformations[k].Type
	t != "NONE"
}

# labels cost 1 WCU per 5 across the container (CheckCapacity: two rules with one label each -> +1)
_pf_wafcap_labels(name) := ceil(n / 5) if {
	rules := _pf_waflib_rules(name)
	n := sum([count(l) | some i; l := rules[i].RuleLabels; is_array(l)])
}

_pf_wafcap_total(name) := t if {
	leaves := sum([c | some [nm, i, p, kind, c] in _pf_wafcap_leaf; nm == name])
	tts := 10 * count({[fj, ty] | some [nm, fj, ty] in _pf_wafcap_tt; nm == name})
	pres := 10 * count({[i, p, kind, k] | some [nm, i, p, kind, k] in _pf_wafcap_pre; nm == name})
	t := ((leaves + tts) + pres) + _pf_wafcap_labels(name)
}

# ponytail: the estimate ignores AWS's cross-rule optimizations beyond transformation sharing,
# so it can only overshoot when two rules share more than a transformation; check-capacity is the oracle.
violation contains make_diag_full("pf-wafv2-capacity", "ERROR", name, "Properties.Capacity",
	sprintf("the rules need about %d WCUs but Capacity is %d; the create call fails with \"You exceeded the capacity limit for a rule group or web ACL.\" (verify with aws wafv2 check-capacity)", [t, c]),
	_pf_wafcap_fix, _pf_wafcap_url) if {
	some name in resources_of_type("AWS::WAFv2::RuleGroup")
	c := resolve(name, "Properties.Capacity")
	is_number(c)
	t := _pf_wafcap_total(name)
	t > c
}

violation contains make_diag_full("pf-wafv2-capacity", "ERROR", name, "Properties.Rules",
	sprintf("the rules need about %d WCUs; a web ACL is limited to 5,000 (the create call fails with \"You exceeded the capacity limit for a rule group or web ACL.\")", [t]),
	_pf_wafcap_fix, _pf_wafcap_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	t := _pf_wafcap_total(name)
	t > 5000
}
