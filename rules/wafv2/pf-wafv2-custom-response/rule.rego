package cdk_preflight

import rego.v1

_pf_wafcr_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_CustomResponse.html"

_pf_wafcr_fix := "Reference a key defined in CustomResponseBodies of the same web ACL / rule group, keep response headers unique and free of content-type (at most 10), and keep each body under 4,096 bytes with at most 50 bodies totalling 50 KB"

# every CustomResponse object: [container, path, object]
_pf_wafcr contains [name, sprintf("Properties.Rules[%d].Action.Block.CustomResponse", [i]), cr] if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	cr := rules[i].Action.Block.CustomResponse
	is_object(cr)
}

_pf_wafcr contains [name, "Properties.DefaultAction.Block.CustomResponse", cr] if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	cr := input.resources[name].properties.DefaultAction.Block.CustomResponse
	is_object(cr)
}

_pf_wafcr contains [name, sprintf("%s.RuleActionOverrides[%d].ActionToUse.Block.CustomResponse", [_pf_waflib_path(i, array.concat(p, [kind])), o]), cr] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	some o
	cr := body.RuleActionOverrides[o].ActionToUse.Block.CustomResponse
	is_object(cr)
}

_pf_wafcr_hdrs(cr) := h if {
	h := cr.ResponseHeaders
	is_array(h)
}

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, sprintf("%s.ResponseHeaders[%d].Name", [pp, k]),
	"content-type cannot be set in a custom response; the create call fails with \"UNSUPPORTED_PARAMETER_VALUE\"",
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some [name, pp, cr] in _pf_wafcr
	h := _pf_wafcr_hdrs(cr)
	some k
	lower(h[k].Name) == "content-type"
}

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, sprintf("%s.ResponseHeaders[%d].Name", [pp, m]),
	sprintf("header '%s' is already set at ResponseHeaders[%d] (names are compared case-insensitively); the create call fails with \"You have duplicated some of the information in the parameter.\"", [h[m].Name, k]),
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some [name, pp, cr] in _pf_wafcr
	h := _pf_wafcr_hdrs(cr)
	some k, m
	k < m
	lower(h[k].Name) == lower(h[m].Name)
}

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, sprintf("%s.ResponseHeaders", [pp]),
	sprintf("%d response headers; a custom response allows at most 10 (the create call fails with WAFLimitsExceededException)", [count(h)]),
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some [name, pp, cr] in _pf_wafcr
	h := _pf_wafcr_hdrs(cr)
	count(h) > 10
}

_pf_wafcr_bodies(name) := b if {
	b := input.resources[name].properties.CustomResponseBodies
	is_object(b)
}

_pf_wafcr_bodies(name) := {} if {
	object.get(input.resources[name].properties, "CustomResponseBodies", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, sprintf("%s.CustomResponseBodyKey", [pp]),
	sprintf("no CustomResponseBodies entry named '%s' on this %s; the create call fails with \"AWS WAF couldn't find a resource that a parameter references.\"", [key, kind]),
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some [name, pp, cr] in _pf_wafcr
	key := cr.CustomResponseBodyKey
	is_string(key)
	bodies := _pf_wafcr_bodies(name)
	object.get(bodies, key, "__pf_absent") == "__pf_absent"
	kind := _pf_wafcr_kind(name)
}

_pf_wafcr_kind(name) := "web ACL" if _pf_waflib_is_webacl(name)

_pf_wafcr_kind(name) := "rule group" if _pf_waflib_is_rulegroup(name)

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, "Properties.CustomResponseBodies",
	sprintf("%d custom response bodies; at most 50 per web ACL / rule group (the create call fails with WAFLimitsExceededException NUM_CUSTOM_RESPONSE_BODY_IN_CONTAINER)", [count(b)]),
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some name in _pf_waflib_containers
	b := _pf_wafcr_bodies(name)
	count(b) > 50
}

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, sprintf("Properties.CustomResponseBodies.%s.Content", [k]),
	sprintf("body is %d characters; a single custom response body is limited to 4,096 bytes even though the schema allows 10,240 (the create call fails with WAFLimitsExceededException)", [count(c)]),
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some name in _pf_waflib_containers
	b := _pf_wafcr_bodies(name)
	some k
	c := b[k].Content
	is_string(c)
	count(c) > 4096
}

violation contains make_diag_full("pf-wafv2-custom-response", "ERROR", name, "Properties.CustomResponseBodies",
	sprintf("bodies total %d characters; all custom response bodies of a web ACL / rule group are limited to 50 KB (the create call fails with WAFLimitsExceededException TOTAL_SIZE_CUSTOM_RESPONSE_BODY_IN_CONTAINER_IN_KB)", [total]),
	_pf_wafcr_fix, _pf_wafcr_url) if {
	some name in _pf_waflib_containers
	b := _pf_wafcr_bodies(name)
	total := sum([n | some k; c := b[k].Content; is_string(c); n := count(c)])
	total > 51200
}
