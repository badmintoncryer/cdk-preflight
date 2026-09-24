package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-samplingrule-name-or-arn-required", "ERROR", name,
	"Properties.SamplingRule",
	"SamplingRule sets neither RuleName nor RuleARN; CreateSamplingRule fails with \"Request must contain either sampling rule name or sampling rule ARN\"",
	"Name the rule with RuleName",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-samplingrule-samplingrule.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	not _pf_xraylib_has(sr, "RuleName")
	not _pf_xraylib_has(sr, "RuleARN")
}
