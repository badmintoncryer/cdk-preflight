package cdk_preflight

import rego.v1

_pf_ecsfargcm_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-taskdefinition.html"

# The engine's E3047 checks the Cpu/Memory pairing only when both are present;
# leaving one out entirely is caught by nothing before registration. True
# absence needs the preprocessed document (see pf-ecs-container-memory-required
# for the idiom).
_pf_ecsfargcm_fargate(name) if {
	some rc in flatten_list(name, "Properties.RequiresCompatibilities")
	rc.value == "FARGATE"
}

_pf_ecsfargcm_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ecs-fargate-task-cpu-memory", "ERROR", name,
	"Properties.Cpu",
	"RequiresCompatibilities includes FARGATE but the task-level Cpu is missing; RegisterTaskDefinition fails with \"Fargate requires that 'cpu' be defined at the task level\"",
	"Set task-level Cpu (and Memory) to one of the supported Fargate combinations",
	_pf_ecsfargcm_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecsfargcm_fargate(name)
	_pf_ecsfargcm_absent(name, "Cpu")
}

violation contains make_diag_full("pf-ecs-fargate-task-cpu-memory", "ERROR", name,
	"Properties.Memory",
	"RequiresCompatibilities includes FARGATE but the task-level Memory is missing; RegisterTaskDefinition fails with \"Fargate requires that 'memory' be defined at the task level\"",
	"Set task-level Memory (and Cpu) to one of the supported Fargate combinations",
	_pf_ecsfargcm_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecsfargcm_fargate(name)
	_pf_ecsfargcm_absent(name, "Memory")
}
