package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-resourcepolicy-name-pattern", "ERROR", name,
	"Properties.PolicyName",
	msg,
	"Use only word characters and + = , . @ - in the policy name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-xray-resourcepolicy.html") if {
	some name in resources_of_type("AWS::XRay::ResourcePolicy")
	n := object.get(_pf_xraylib_props(name), "PolicyName", null)
	is_string(n)
	not regex.match(`^[\w+=,.@-]+$`, n)
	msg := sprintf("PolicyName '%s' has characters outside [\\w+=,.@-]; PutResourcePolicy rejects it (the CloudFormation schema carries the same pattern but unanchored, so a partial match slips through)", [n])
}
