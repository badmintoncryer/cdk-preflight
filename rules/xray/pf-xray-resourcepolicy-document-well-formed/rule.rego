package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-resourcepolicy-document-well-formed", "ERROR", name,
	"Properties.PolicyDocument",
	"PolicyDocument is not valid JSON; PutResourcePolicy fails with MalformedPolicyDocumentException",
	"Build the document with JSON.stringify or iam.PolicyDocument#toJSON",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-xray-resourcepolicy.html") if {
	some name in resources_of_type("AWS::XRay::ResourcePolicy")
	raw := _pf_xraylib_policy(name)
	not json.is_valid(raw)
}

violation contains make_diag_full("pf-xray-resourcepolicy-document-well-formed", "ERROR", name,
	p,
	"a statement of this resource policy names no Principal; a resource policy without one is rejected by PutResourcePolicy with MalformedPolicyDocumentException",
	"Add a Principal to every statement (an X-Ray resource policy is a resource-based policy)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-xray-resourcepolicy.html") if {
	some name in resources_of_type("AWS::XRay::ResourcePolicy")
	raw := _pf_xraylib_policy(name)
	json.is_valid(raw)
	doc := json.unmarshal(raw)
	some st in _pf_xraylib_stmts(doc)
	not _pf_xraylib_has(st[1], "Principal")
	not _pf_xraylib_has(st[1], "NotPrincipal")
	p := sprintf("Properties.PolicyDocument.Statement.%v", [st[0]])
}
