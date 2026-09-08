package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-cluster-execute-command-default-with-log-config", "ERROR", name,
	"Properties.Configuration.ExecuteCommandConfiguration.Logging",
	sprintf("ExecuteCommandConfiguration supplies a LogConfiguration with Logging '%s'; CreateCluster fails with \"You must set logging to 'OVERRIDE' when you supply a log configuration\"", [lg]),
	"Set Logging to 'OVERRIDE', or drop LogConfiguration",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::ECS::Cluster")
	cfg := _pf_ecs_get(name, "Configuration")
	ec := _pf_ecs_oget(cfg, "ExecuteCommandConfiguration")
	_pf_ecs_ohas(ec, "LogConfiguration")
	lg := _pf_ecs_oget(ec, "Logging")
	_pf_ecs_lit(lg)
	lg != "OVERRIDE"
}
