package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-samplingrule-name-arn-exclusive", "ERROR", name,
	"Properties.SamplingRule.RuleARN",
	"SamplingRule carries both RuleName and RuleARN; CreateSamplingRule fails with \"Request cannot contain both sampling rule name and sampling rule ARN\"",
	"Keep RuleName when CloudFormation creates the rule and drop RuleARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-samplingrule-samplingrule.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	_pf_xraylib_has(sr, "RuleName")
	_pf_xraylib_has(sr, "RuleARN")
}
