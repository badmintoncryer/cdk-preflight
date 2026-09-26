package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rp-policy-statement-required", "ERROR", name,
	"Properties.PolicyDocument",
	"PolicyDocument has no Statement; PutResourcePolicy fails with \"Workspace resource policy cannot be malformed\"",
	"Give the policy a Statement list",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-resourcepolicy.html") if {
	some name in resources_of_type("AWS::APS::ResourcePolicy")
	pol := _pf_aps_policy(name)
	object.get(pol, "Statement", "__pf_absent") == "__pf_absent"
}
