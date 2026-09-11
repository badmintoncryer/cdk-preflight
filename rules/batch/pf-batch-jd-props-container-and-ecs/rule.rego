package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-props-container-and-ecs", "ERROR", name,
	"Properties.EcsProperties",
	"ContainerProperties and EcsProperties cannot both be set (\"Cannot use both ECS containerProperties and ecsProperties\")",
	"Keep either ContainerProperties or EcsProperties",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-batch-jobdefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_cp(name)
	_pf_batch_has(name, "EcsProperties")
}
