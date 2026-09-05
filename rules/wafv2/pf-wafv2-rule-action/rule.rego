package cdk_preflight

import rego.v1

_pf_wafact_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-webacl-rule.html"

_pf_wafact_fix := "Set OverrideAction: { None: {} } (or Count) on ManagedRuleGroupStatement / RuleGroupReferenceStatement rules and a single Action (Allow / Block / Count / Captcha / Challenge) on all other rules; rate-based rules cannot Allow"

_pf_wafact_refs := {"ManagedRuleGroupStatement", "RuleGroupReferenceStatement"}

_pf_wafact_has(r, k) if object.get(r, k, "__pf_absent") != "__pf_absent"

_pf_wafact_msg := "the create call fails with \"You have used none or multiple values for a field that requires exactly one value.\""

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, sprintf("Properties.Rules[%d]", [i]),
	sprintf("rule '%s' sets both Action and OverrideAction; %s", [rules[i].Name, _pf_wafact_msg]),
	_pf_wafact_fix, _pf_wafact_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	_pf_wafact_has(rules[i], "Action")
	_pf_wafact_has(rules[i], "OverrideAction")
}

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, sprintf("Properties.Rules[%d]", [i]),
	sprintf("rule '%s' sets neither Action nor OverrideAction; %s", [rules[i].Name, _pf_wafact_msg]),
	_pf_wafact_fix, _pf_wafact_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	not _pf_wafact_has(rules[i], "Action")
	not _pf_wafact_has(rules[i], "OverrideAction")
}

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, sprintf("Properties.Rules[%d].Action", [i]),
	sprintf("a %s rule takes OverrideAction, not Action; the create call fails with \"A reference in your rule statement is not valid.\"", [kind]),
	_pf_wafact_fix, _pf_wafact_url) if {
	some [name, i, kind] in _pf_waflib_tops
	kind in _pf_wafact_refs
	rules := _pf_waflib_rules(name)
	_pf_wafact_has(rules[i], "Action")
	not _pf_wafact_has(rules[i], "OverrideAction")
}

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, sprintf("Properties.Rules[%d].OverrideAction", [i]),
	sprintf("OverrideAction is only for rule group references, but this rule's statement is %s; %s", [kind, _pf_wafact_msg]),
	_pf_wafact_fix, _pf_wafact_url) if {
	some [name, i, kind] in _pf_waflib_tops
	not kind in _pf_wafact_refs
	rules := _pf_waflib_rules(name)
	_pf_wafact_has(rules[i], "OverrideAction")
	not _pf_wafact_has(rules[i], "Action")
}

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, sprintf("Properties.Rules[%d].%s", [i, k]),
	sprintf("%s names %d actions; it must name exactly one (EXACTLY_ONE_CONDITION_REQUIRED)", [k, count(object.keys(a))]),
	_pf_wafact_fix, _pf_wafact_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	some k in {"Action", "OverrideAction"}
	a := rules[i][k]
	is_object(a)
	count(object.keys(a)) != 1
}

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, "Properties.DefaultAction",
	sprintf("DefaultAction names %d actions; it must be exactly one of Allow / Block; %s", [count(object.keys(a)), _pf_wafact_msg]),
	_pf_wafact_fix, _pf_wafact_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	a := input.resources[name].properties.DefaultAction
	is_object(a)
	count(object.keys(a)) != 1
}

violation contains make_diag_full("pf-wafv2-rule-action", "ERROR", name, sprintf("Properties.Rules[%d].Action.Allow", [i]),
	"a rate-based rule cannot use the Allow action; the create call fails with \"The parameter value isn't supported.\"",
	_pf_wafact_fix, _pf_wafact_url) if {
	some [name, i, kind] in _pf_waflib_tops
	kind == "RateBasedStatement"
	rules := _pf_waflib_rules(name)
	rules[i].Action.Allow
}
