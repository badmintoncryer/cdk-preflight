package cdk_preflight

import rego.v1

_pf_ecrlps_url := "https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_parameters.html"

_pf_ecrlps_fix := "Write the policy as {\"rules\":[{\"rulePriority\":1,\"selection\":{...},\"action\":{\"type\":\"expire\"}}]} — PutLifecyclePolicy rejects unknown keys and accepts at most 50 rules"

_pf_ecrlps_rule_keys := {"rulePriority", "description", "selection", "action"}

_pf_ecrlps_selection_keys := {"tagStatus", "tagPrefixList", "tagPatternList", "countType", "countUnit", "countNumber", "storageClass"}

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	_pf_ecrlib_prop(name),
	"the lifecycle policy is not a JSON object; PutLifecyclePolicy fails with \"Lifecycle policy parsing failure: Could not map policyString into LifecyclePolicy\"",
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some name, _ in input.resources
	_pf_ecrlib_text(name)
	not _pf_ecrlib_policy(name)
}

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	_pf_ecrlib_prop(name),
	"the lifecycle policy has no \"rules\" array; PutLifecyclePolicy fails with \"object has missing required properties ([\\\"rules\\\"])\"",
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some name, _ in input.resources
	_pf_ecrlib_policy(name)
	not _pf_ecrlib_rule_list(name)
}

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	_pf_ecrlib_prop(name),
	sprintf("the lifecycle policy has %d rules; PutLifecyclePolicy accepts 1 to 50 (\"array is too long\" / \"array is too short\")", [count(rules)]),
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some name, _ in input.resources
	rules := _pf_ecrlib_rule_list(name)
	_pf_ecrlps_bad_count(count(rules))
}

_pf_ecrlps_bad_count(n) if n < 1

_pf_ecrlps_bad_count(n) if n > 50

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	sprintf("%s[%d]", [_pf_ecrlib_prop(name), i]),
	sprintf("lifecycle rule %d has no \"%s\"; PutLifecyclePolicy fails with \"object has missing required properties\"", [i, key]),
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	some key in ["rulePriority", "selection", "action"]
	_pf_ecrlib_absent(rule, key)
}

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	sprintf("%s[%d]", [_pf_ecrlib_prop(name), i]),
	sprintf("lifecycle rule %d has the unknown key \"%s\"; PutLifecyclePolicy fails with \"object instance has properties which are not allowed by the schema\"", [i, key]),
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	some key, _ in rule
	not key in _pf_ecrlps_rule_keys
}

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	sprintf("%s[%d].selection", [_pf_ecrlib_prop(name), i]),
	sprintf("lifecycle rule %d has the unknown selection key \"%s\"; PutLifecyclePolicy fails with \"object instance has properties which are not allowed by the schema\"", [i, key]),
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	some key, _ in _pf_ecrlib_selection(rule)
	not key in _pf_ecrlps_selection_keys
}

violation contains make_diag_full("pf-ecr-lifecycle-policy-syntax", "ERROR", name,
	sprintf("%s[%d].selection", [_pf_ecrlib_prop(name), i]),
	sprintf("lifecycle rule %d does not set \"%s\" in its selection; PutLifecyclePolicy fails with \"object has missing required properties\"", [i, key]),
	_pf_ecrlps_fix, _pf_ecrlps_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	some key in ["tagStatus", "countType", "countNumber"]
	_pf_ecrlib_absent(sel, key)
}
