package cdk_preflight

import rego.v1

_pf_iotpolst_has(d) if is_object(object.get(d, "Statement", null))

_pf_iotpolst_has(d) if {
	s := object.get(d, "Statement", null)
	is_array(s)
	count(s) > 0
}

violation contains make_diag_full("pf-iot-policy-document-statement", "ERROR", name,
	path,
	"the policy document has no Statement; the stack event reads \"Policy document is Malformed: Policy has no statements\"",
	"Add a Statement list to the policy document",
	"https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html") if {
	some [name, path, d] in _pf_iotlib_policy_docs
	not _pf_iotpolst_has(d)
}
