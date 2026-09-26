package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rp-action-no-wildcard", "ERROR", name,
	"Properties.PolicyDocument",
	sprintf("Action %v uses a wildcard; PutResourcePolicy fails with \"Resource policy contains actions that are not supported\"", [a]),
	"List the aps: actions one by one (aps:RemoteWrite, aps:QueryMetrics, aps:GetLabels, aps:GetSeries, aps:GetMetricMetadata)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-resourcepolicy.html") if {
	some name in resources_of_type("AWS::APS::ResourcePolicy")
	some s in _pf_aps_policy_statements(name)
	some a in _pf_aps_policy_strings(s, "Action")
	contains(a, "*")
}
