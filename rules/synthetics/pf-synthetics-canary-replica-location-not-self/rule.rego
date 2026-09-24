package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-replica-location-not-self", "ERROR", name,
	sprintf("Properties.Replicas.%v.Location", [it.index]),
	sprintf("A replica is asked for in '%s', which is where the canary itself deploys; a multi-location canary replicates to other Regions and the primary is not one of its own replicas", [region]),
	"Name another Region in Replicas[].Location, or drop the replica",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-replica.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some it in flatten_list(name, "Properties.Replicas")
	object.get(it.value, "Location", null) == region
}
