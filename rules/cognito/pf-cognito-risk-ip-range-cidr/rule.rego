package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-risk-ip-range-cidr", "ERROR", name,
	sprintf("Properties.RiskExceptionConfiguration.BlockedIPRangeList.%d", [r.index]),
	sprintf("'%s' is not a CIDR block; the risk configuration call fails with \"Incorrect CIDR format\"", [v]),
	"Write the range as CIDR, e.g. 203.0.113.0/24",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolriskconfigurationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolRiskConfigurationAttachment")
	some r in flatten_list(name, "Properties.RiskExceptionConfiguration.BlockedIPRangeList")
	v := r.value
	is_string(v)
	not contains(v, "/")
}
