package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-props-container-and-eks", "ERROR", name,
	"Properties.EksProperties",
	"ContainerProperties and EksProperties cannot both be set (\"Cannot use both ECS containerProperties and eksProperties\")",
	"Keep either ContainerProperties or EksProperties",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-batch-jobdefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_cp(name)
	_pf_batch_has(name, "EksProperties")
}
