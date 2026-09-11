package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-container-type-requires-props", "ERROR", name,
	"Properties.ContainerProperties",
	"a container job definition sets none of ContainerProperties, EcsProperties or EksProperties; the create fails with \"ECS Container Image must be provided.\"",
	"Add ContainerProperties, EcsProperties or EksProperties",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_get(name, "Type") == "container"
	not _pf_batch_has(name, "ContainerProperties")
	not _pf_batch_has(name, "EcsProperties")
	not _pf_batch_has(name, "EksProperties")
}
