package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-policy-document-version", "ERROR", name,
	sprintf("%s.Version", [path]),
	sprintf("the policy document declares Version '%s'; the stack event reads \"Policy document is Malformed: Unknown policy document version. It must be version 2012-10-17\"", [v]),
	"Set the document Version to 2012-10-17",
	"https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html") if {
	some [name, path, d] in _pf_iotlib_policy_docs
	v := object.get(d, "Version", null)
	is_string(v)
	v != "2012-10-17"
}
