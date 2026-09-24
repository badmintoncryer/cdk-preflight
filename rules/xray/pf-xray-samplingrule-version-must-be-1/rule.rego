package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-samplingrule-version-must-be-1", "ERROR", name,
	"Properties.SamplingRule.Version",
	msg,
	"Set Version to 1",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-samplingrule-samplingrule.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	v := to_number(object.get(sr, "Version", 1))
	v > 1
	msg := sprintf("SamplingRule.Version is %v; CreateSamplingRule fails with \"Sampling rule version must be 1\" (the CloudFormation schema only has a minimum of 1)", [v])
}
