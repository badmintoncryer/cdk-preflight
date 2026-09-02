package cdk_preflight

import rego.v1

_pf_ecseph_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-ephemeralstorage.html"

# The registry schema carries no minimum/maximum for SizeInGiB, so 21-200 is
# enforced only at registration time.
violation contains make_diag_full("pf-ecs-ephemeral-storage-range", "ERROR", name,
	"Properties.EphemeralStorage.SizeInGiB",
	sprintf("EphemeralStorage SizeInGiB %v is below 21; RegisterTaskDefinition fails with \"EphemeralStorage size should be at least 21\"", [s]),
	"Use a size between 21 and 200 GiB, or drop EphemeralStorage to keep the default 20 GiB",
	_pf_ecseph_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	s := to_number(resolve(name, "Properties.EphemeralStorage.SizeInGiB"))
	s < 21
}

violation contains make_diag_full("pf-ecs-ephemeral-storage-range", "ERROR", name,
	"Properties.EphemeralStorage.SizeInGiB",
	sprintf("EphemeralStorage SizeInGiB %v is above 200; RegisterTaskDefinition fails with \"EphemeralStorage size should be at most 200\"", [s]),
	"Use a size between 21 and 200 GiB",
	_pf_ecseph_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	s := to_number(resolve(name, "Properties.EphemeralStorage.SizeInGiB"))
	s > 200
}
