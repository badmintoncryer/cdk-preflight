package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-samplingrule-name-reserved-default", "ERROR", name,
	"Properties.SamplingRule.RuleName",
	"RuleName is Default, which every account already has as its built-in sampling rule; CreateSamplingRule fails with \"Sampling rule already exists\"",
	"Pick another RuleName; the built-in Default rule is edited in place, not recreated",
	"https://docs.aws.amazon.com/xray/latest/devguide/xray-console-sampling.html") if {
	some name in resources_of_type("AWS::XRay::SamplingRule")
	sr := _pf_xraylib_sr(name)
	object.get(sr, "RuleName", null) == "Default"
}
