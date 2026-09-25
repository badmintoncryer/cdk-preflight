package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-policy-document-effect", "ERROR", name,
	sprintf("%s.Statement.%d.Effect", [path, i]),
	sprintf("Effect '%s' is neither Allow nor Deny; the stack event reads \"Policy document is Malformed: Invalid effect: %s\"", [e, e]),
	"Write Allow or Deny",
	"https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html") if {
	some [name, path, d] in _pf_iotlib_policy_docs
	some [i, s] in _pf_iamlib_stmts(d)
	e := object.get(s, "Effect", null)
	is_string(e)
	not e in {"Allow", "Deny"}
}
