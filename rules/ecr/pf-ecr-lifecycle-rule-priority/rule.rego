package cdk_preflight

import rego.v1

_pf_ecrlpr_url := "https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_parameters.html"

_pf_ecrlpr_fix := "Give every rule a distinct rulePriority >= 1 and let the tagStatus=any rule (at most one) have the highest number"

_pf_ecrlpr_prio(rule) := p if {
	p := object.get(rule, "rulePriority", null)
	is_number(p)
}

_pf_ecrlpr_any(name) := [i | some [n, i, rule] in _pf_ecrlib_rules; n == name; object.get(_pf_ecrlib_selection(rule), "tagStatus", "") == "any"]

violation contains make_diag_full("pf-ecr-lifecycle-rule-priority", "ERROR", name,
	sprintf("%s[%d].rulePriority", [_pf_ecrlib_prop(name), i]),
	sprintf("rulePriority %d is used by more than one rule; PutLifecyclePolicy fails with \"Duplicate priority in multiple rules\"", [p]),
	_pf_ecrlpr_fix, _pf_ecrlpr_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	p := _pf_ecrlpr_prio(rule)
	some [n2, j, other] in _pf_ecrlib_rules
	n2 == name
	j != i
	_pf_ecrlpr_prio(other) == p
}

violation contains make_diag_full("pf-ecr-lifecycle-rule-priority", "ERROR", name,
	sprintf("%s[%d].rulePriority", [_pf_ecrlib_prop(name), i]),
	sprintf("rulePriority is %d; PutLifecyclePolicy accepts positive integers only (\"numeric instance is lower than the required minimum\")", [p]),
	_pf_ecrlpr_fix, _pf_ecrlpr_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	p := _pf_ecrlpr_prio(rule)
	p < 1
}

violation contains make_diag_full("pf-ecr-lifecycle-rule-priority", "ERROR", name,
	sprintf("%s[%d].selection.tagStatus", [_pf_ecrlib_prop(name), i]),
	sprintf("the tagStatus=any rule has rulePriority %d but another rule has %d; PutLifecyclePolicy fails with \"Rule for tagStatus=ANY must have the highest rulePriority\"", [p, q]),
	_pf_ecrlpr_fix, _pf_ecrlpr_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	object.get(_pf_ecrlib_selection(rule), "tagStatus", "") == "any"
	p := _pf_ecrlpr_prio(rule)
	some [n2, j, other] in _pf_ecrlib_rules
	n2 == name
	j != i
	q := _pf_ecrlpr_prio(other)
	q > p
}

violation contains make_diag_full("pf-ecr-lifecycle-rule-priority", "ERROR", name,
	_pf_ecrlib_prop(name),
	sprintf("%d rules use tagStatus=any; PutLifecyclePolicy fails with \"Only one rule can specify tagStatus=ANY\"", [count(anys)]),
	_pf_ecrlpr_fix, _pf_ecrlpr_url) if {
	some name, _ in input.resources
	anys := _pf_ecrlpr_any(name)
	count(anys) > 1
}
