package cdk_preflight

import rego.v1

_pf_ecsesro_on(es) if _pf_ecs_oget(es, "Enable") in {true, "true"}

violation contains make_diag_full("pf-ecs-svc-early-success-rolling-only", "ERROR", name,
	"Properties.DeploymentConfiguration.EarlySuccessCriteria",
	sprintf("EarlySuccessCriteria is enabled with Strategy %s; CreateService fails with \"Early success criteria not supported for %s deployment strategy\"", [s, s]),
	"Use Strategy ROLLING, or remove EarlySuccessCriteria",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-early-success.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	dc := _pf_ecs_get(name, "DeploymentConfiguration")
	es := _pf_ecs_oget(dc, "EarlySuccessCriteria")
	_pf_ecsesro_on(es)
	s := _pf_ecs_oget(dc, "Strategy")
	s in {"BLUE_GREEN", "LINEAR", "CANARY"}
}
