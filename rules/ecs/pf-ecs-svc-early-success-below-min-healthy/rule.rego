package cdk_preflight

import rego.v1

_pf_ecsesmh_on(es) if _pf_ecs_oget(es, "Enable") in {true, "true"}

_pf_ecsesmh_num(o, k) := n if {
	v := _pf_ecs_oget(o, k)
	not is_boolean(v)
	v != null
	n := _pf_tonum(v)
}

violation contains make_diag_full("pf-ecs-svc-early-success-below-min-healthy", "ERROR", name,
	"Properties.DeploymentConfiguration.EarlySuccessCriteria.HealthyPercent",
	sprintf("EarlySuccessCriteria.HealthyPercent %v is below MinimumHealthyPercent %v; CreateService fails with \"Invalid early success criteria, healthy percent must be between minimum healthy percent and 100.\"", [hp, mn]),
	"Raise HealthyPercent to at least MinimumHealthyPercent (and at most 100)",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-early-success.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	dc := _pf_ecs_get(name, "DeploymentConfiguration")
	es := _pf_ecs_oget(dc, "EarlySuccessCriteria")
	_pf_ecsesmh_on(es)
	hp := _pf_ecsesmh_num(es, "HealthyPercent")
	mn := _pf_ecsesmh_num(dc, "MinimumHealthyPercent")
	hp < mn
}
