package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-cp-name-reserved-prefix", "ERROR", name,
	"Properties.Name",
	sprintf("The capacity provider name '%s' uses a reserved prefix; CreateCapacityProvider fails with \"The specified capacity provider name is invalid\"", [n]),
	"Rename the capacity provider so it does not start with aws, ecs or fargate",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCapacityProvider.html") if {
	some name in resources_of_type("AWS::ECS::CapacityProvider")
	n := resolve(name, "Properties.Name")
	_pf_ecs_lit(n)
	some p in {"aws", "ecs", "fargate"}
	startswith(lower(n), p)
}
