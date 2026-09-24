package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-resourcepolicy-xray-actions-only", "ERROR", name,
	p,
	msg,
	"Grant only xray: actions in an X-Ray resource policy",
	"https://docs.aws.amazon.com/xray/latest/api/API_PutResourcePolicy.html") if {
	some name in resources_of_type("AWS::XRay::ResourcePolicy")
	raw := _pf_xraylib_policy(name)
	json.is_valid(raw)
	doc := json.unmarshal(raw)
	some st in _pf_xraylib_stmts(doc)
	some act in _pf_xraylib_list(object.get(st[1], "Action", null))
	is_string(act)
	contains(act, ":")
	split(act, ":")[0] != "xray"
	p := sprintf("Properties.PolicyDocument.Statement.%v.Action", [st[0]])
	msg := sprintf("the resource policy grants '%s'; PutResourcePolicy rejects a document with any action outside the xray: namespace (MalformedPolicyDocumentException)", [act])
}
