package cdk_preflight

import rego.v1

_pf_apsrw_fix := "Point every Resource at the workspace the policy is attached to"

_pf_apsrw_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-resourcepolicy.html"

# The workspace is imported, so its ARN is in the template and every Resource
# must equal it verbatim - PutResourcePolicy rejects "*" the same way.
violation contains make_diag_full("pf-aps-rp-policy-resource-workspace", "ERROR", name,
	"Properties.PolicyDocument",
	sprintf("a statement grants on %v but the policy is attached to %v; PutResourcePolicy fails with \"Resource in policy does not match workspace resource ARN\"", [r, arn]),
	_pf_apsrw_fix, _pf_apsrw_url) if {
	some name in resources_of_type("AWS::APS::ResourcePolicy")
	arn := _pf_aps_str(name, "Properties.WorkspaceArn")
	startswith(arn, "arn:")
	some s in _pf_aps_policy_statements(name)
	some r in _pf_aps_policy_strings(s, "Resource")
	r != arn
}

# The workspace is created by this template, so its id does not exist yet and no
# literal ARN written into the policy can name it. resolve() turns the Ref /
# Fn::GetAtt into the logical id, and requiring that id to be an
# AWS::APS::Workspace keeps the rule off an ARN handed in by some other resource.
violation contains make_diag_full("pf-aps-rp-policy-resource-workspace", "ERROR", name,
	"Properties.PolicyDocument",
	sprintf("a statement grants on %v while the policy is attached to the workspace %v created by this template, whose ARN is not known until deploy; PutResourcePolicy fails with \"Resource in policy does not match workspace resource ARN\"", [r, ws]),
	_pf_apsrw_fix, _pf_apsrw_url) if {
	some name in resources_of_type("AWS::APS::ResourcePolicy")
	some ws in resources_of_type("AWS::APS::Workspace")
	_pf_aps_str(name, "Properties.WorkspaceArn") == ws
	some s in _pf_aps_policy_statements(name)
	some r in _pf_aps_policy_strings(s, "Resource")
}
