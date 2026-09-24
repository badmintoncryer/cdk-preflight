package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-samplingrule-attribute-key-max-32", "ERROR", name,
	p,
	msg,
	"Shorten the attribute key to 32 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-samplingrule-samplingrule.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	attrs := object.get(sr, "Attributes", null)
	is_object(attrs)
	some k in object.keys(attrs)
	count(k) > 32
	p := sprintf("Properties.SamplingRule.Attributes.%s", [k])
	msg := sprintf("SamplingRule.Attributes key '%s' is %d characters; CreateSamplingRule requires every attribute key and value to be 1-32 characters", [k, count(k)])
}

violation contains make_diag_full("pf-xray-samplingrule-attribute-key-max-32", "ERROR", name,
	p,
	msg,
	"Shorten the attribute value to 32 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-samplingrule-samplingrule.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	attrs := object.get(sr, "Attributes", null)
	is_object(attrs)
	some k, v in attrs
	is_string(v)
	count(v) > 32
	p := sprintf("Properties.SamplingRule.Attributes.%s", [k])
	msg := sprintf("SamplingRule.Attributes value for '%s' is %d characters; CreateSamplingRule requires every attribute key and value to be 1-32 characters", [k, count(v)])
}
