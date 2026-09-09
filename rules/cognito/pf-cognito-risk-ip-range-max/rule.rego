package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-risk-ip-range-max", "ERROR", name,
	"Properties.RiskExceptionConfiguration.BlockedIPRangeList",
	sprintf("the blocked IP range list has %d entries; the risk configuration call fails with \"Member must have length less than or equal to 200\"", [count(rs)]),
	"Keep BlockedIPRangeList at 200 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolriskconfigurationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolRiskConfigurationAttachment")
	rs := flatten_list(name, "Properties.RiskExceptionConfiguration.BlockedIPRangeList")
	count(rs) > 200
}
