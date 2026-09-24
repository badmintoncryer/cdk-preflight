package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-dependency-layer-region", "ERROR", name,
	sprintf("Properties.Code.Dependencies.%v.Reference", [it.index]),
	sprintf("The dependency layer is in '%s' but the canary deploys to '%s'; Synthetics resolves the layer through Lambda in its own Region, which answers \"Invalid Layer name\" for an ARN of another Region", [r, region]),
	"Publish the layer in the deploy Region and reference that ARN (build it with ${AWS::Region})",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-dependency.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some it in flatten_list(name, "Properties.Code.Dependencies")
	r := _pf_synlib_arn_region(object.get(it.value, "Reference", null), "lambda")
	r != region
}
