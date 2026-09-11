package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-props-ecs-and-eks", "ERROR", name,
	"Properties.EksProperties",
	"EcsProperties and EksProperties cannot both be set (\"Cannot use both ecsProperties and eksProperties\")",
	"Keep either EcsProperties or EksProperties",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-batch-jobdefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_has(name, "EcsProperties")
	_pf_batch_has(name, "EksProperties")
}
