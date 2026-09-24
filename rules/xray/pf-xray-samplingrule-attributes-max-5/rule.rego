package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-samplingrule-attributes-max-5", "ERROR", name,
	"Properties.SamplingRule.Attributes",
	msg,
	"Keep at most 5 attributes on the sampling rule",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-samplingrule-samplingrule.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	attrs := object.get(sr, "Attributes", null)
	is_object(attrs)
	n := count(attrs)
	n > 5
	msg := sprintf("SamplingRule.Attributes has %d entries; CreateSamplingRule rejects more than 5 (\"Member must have length less than or equal to 5\")", [n])
}
