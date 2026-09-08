package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-binpack-field", "ERROR", name,
	"Properties.PlacementStrategies",
	sprintf("A binpack placement strategy uses the field '%s'; CreateService fails with \"binpack field '%s' is invalid\"", [f, f]),
	"Set Field to cpu or memory",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some ps in flatten_list(name, "Properties.PlacementStrategies")
	object.get(ps.value, "Type", null) == "binpack"
	f := object.get(ps.value, "Field", null)
	_pf_ecs_lit(f)
	not f in {"cpu", "memory"}
}
