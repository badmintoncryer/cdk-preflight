package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-placement-constraint-distinct-instance-expression", "ERROR", name,
	"Properties.PlacementConstraints",
	"A distinctInstance placement constraint carries an Expression; CreateService fails with \"distinctInstance expression should not be specified\"",
	"Drop Expression from the distinctInstance constraint",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some pc in flatten_list(name, "Properties.PlacementConstraints")
	object.get(pc.value, "Type", null) == "distinctInstance"
	_pf_ecs_ohas(pc.value, "Expression")
}
