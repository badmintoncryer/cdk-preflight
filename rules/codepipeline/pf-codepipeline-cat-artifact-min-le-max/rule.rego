package cdk_preflight

import rego.v1

# A custom action type's artifact counts must not invert.
violation contains make_diag_full("pf-codepipeline-cat-artifact-min-le-max", "ERROR", name,
	sprintf("Properties.%v.MinimumCount", [kind]),
	sprintf("%v has MinimumCount %d and MaximumCount %d; CreateCustomActionType fails with \"Maximum Number of Artifacts (%d) has to be greater than or equal to minimum (%d).\"", [kind, mn, mx, mx, mn]),
	"Raise MaximumCount, or lower MinimumCount to at most MaximumCount",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_CreateCustomActionType.html") if {
	some name in resources_of_type("AWS::CodePipeline::CustomActionType")
	some kind in ["InputArtifactDetails", "OutputArtifactDetails"]
	d := object.get(_pf_cplib_props(name), kind, {})
	_pf_cplib_plain(d)
	mn := to_number(_pf_cplib_get(d, "MinimumCount"))
	mx := to_number(_pf_cplib_get(d, "MaximumCount"))
	mn > mx
}
