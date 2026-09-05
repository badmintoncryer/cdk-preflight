package cdk_preflight

import rego.v1

_pf_wafcrh_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_CustomRequestHandling.html"

_pf_wafcrh_fix := "Keep InsertHeaders names unique, at most 10 per CustomRequestHandling and 100 across the web ACL / rule group"

_pf_wafcrh_acts := {"Allow", "Count", "Captcha", "Challenge"}

# every CustomRequestHandling object: [container, path, object]
_pf_wafcrh contains [name, sprintf("Properties.Rules[%d].Action.%s.CustomRequestHandling", [i, a]), h] if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	some a in _pf_wafcrh_acts
	h := rules[i].Action[a].CustomRequestHandling
	is_object(h)
}

_pf_wafcrh contains [name, sprintf("Properties.Rules[%d].OverrideAction.Count.CustomRequestHandling", [i]), h] if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	h := rules[i].OverrideAction.Count.CustomRequestHandling
	is_object(h)
}

_pf_wafcrh contains [name, "Properties.DefaultAction.Allow.CustomRequestHandling", h] if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	h := input.resources[name].properties.DefaultAction.Allow.CustomRequestHandling
	is_object(h)
}

_pf_wafcrh contains [name, sprintf("%s.RuleActionOverrides[%d].ActionToUse.%s.CustomRequestHandling", [_pf_waflib_path(i, array.concat(p, [kind])), o, a]), h] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	some o
	some a in _pf_wafcrh_acts
	h := body.RuleActionOverrides[o].ActionToUse[a].CustomRequestHandling
	is_object(h)
}

_pf_wafcrh_hdrs(h) := ih if {
	ih := h.InsertHeaders
	is_array(ih)
}

violation contains make_diag_full("pf-wafv2-custom-request-handling", "ERROR", name, sprintf("%s.InsertHeaders[%d].Name", [pp, m]),
	sprintf("header '%s' is already inserted at InsertHeaders[%d]; the create call fails with \"You have duplicated some of the information in the parameter.\"", [ih[m].Name, k]),
	_pf_wafcrh_fix, _pf_wafcrh_url) if {
	some [name, pp, h] in _pf_wafcrh
	ih := _pf_wafcrh_hdrs(h)
	some k, m
	k < m
	lower(ih[k].Name) == lower(ih[m].Name)
}

violation contains make_diag_full("pf-wafv2-custom-request-handling", "ERROR", name, sprintf("%s.InsertHeaders", [pp]),
	sprintf("%d inserted headers; a custom request handling allows at most 10 (the create call fails with WAFLimitsExceededException)", [count(ih)]),
	_pf_wafcrh_fix, _pf_wafcrh_url) if {
	some [name, pp, h] in _pf_wafcrh
	ih := _pf_wafcrh_hdrs(h)
	count(ih) > 10
}

violation contains make_diag_full("pf-wafv2-custom-request-handling", "ERROR", name, "Properties.Rules",
	sprintf("%d inserted request headers across the resource; at most 100 per web ACL / rule group (the create call fails with WAFLimitsExceededException NUM_CUSTOM_REQUEST_HTTPHEADER_IN_CONTAINER)", [total]),
	_pf_wafcrh_fix, _pf_wafcrh_url) if {
	some name in _pf_waflib_containers
	total := sum([n | some [nm, pp, h] in _pf_wafcrh; nm == name; n := count(_pf_wafcrh_hdrs(h))])
	total > 100
}
