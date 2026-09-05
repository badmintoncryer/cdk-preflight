package cdk_preflight

import rego.v1

_pf_ecrlpa_url := "https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_parameters.html"

_pf_ecrlpa_fix := "Use action {\"type\":\"expire\"}, or {\"type\":\"transition\",\"targetStorageClass\":\"archive\"}"

violation contains make_diag_full("pf-ecr-lifecycle-action", "ERROR", name,
	sprintf("%s[%d].action.type", [_pf_ecrlib_prop(name), i]),
	sprintf("action type is '%s'; PutLifecyclePolicy accepts expire or transition", [ty]),
	_pf_ecrlpa_fix, _pf_ecrlpa_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	ty := object.get(_pf_ecrlib_action(rule), "type", null)
	is_string(ty)
	not ty in {"expire", "transition"}
}

violation contains make_diag_full("pf-ecr-lifecycle-action", "ERROR", name,
	sprintf("%s[%d].action", [_pf_ecrlib_prop(name), i]),
	sprintf("rule %d transitions images but does not set targetStorageClass; PutLifecyclePolicy fails with \"Could not map policyString into LifecyclePolicy\"", [i]),
	_pf_ecrlpa_fix, _pf_ecrlpa_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	act := _pf_ecrlib_action(rule)
	object.get(act, "type", null) == "transition"
	_pf_ecrlib_absent(act, "targetStorageClass")
}

violation contains make_diag_full("pf-ecr-lifecycle-action", "ERROR", name,
	sprintf("%s[%d].action.targetStorageClass", [_pf_ecrlib_prop(name), i]),
	sprintf("targetStorageClass is '%s'; archive is the only value a transition action accepts", [tsc]),
	_pf_ecrlpa_fix, _pf_ecrlpa_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	tsc := object.get(_pf_ecrlib_action(rule), "targetStorageClass", null)
	is_string(tsc)
	tsc != "archive"
}
