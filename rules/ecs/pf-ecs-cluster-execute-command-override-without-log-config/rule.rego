package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-cluster-execute-command-override-without-log-config", "ERROR", name,
	"Properties.Configuration.ExecuteCommandConfiguration.LogConfiguration",
	"ExecuteCommandConfiguration overrides the default logging without a LogConfiguration; CreateCluster fails with \"A CloudWatch log group name or S3 bucket name must be specified when overriding the default log configuration\"",
	"Add LogConfiguration with a CloudWatch log group or an S3 bucket",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::ECS::Cluster")
	cfg := _pf_ecs_get(name, "Configuration")
	ec := _pf_ecs_oget(cfg, "ExecuteCommandConfiguration")
	_pf_ecs_oget(ec, "Logging") == "OVERRIDE"
	not _pf_ecs_ohas(ec, "LogConfiguration")
}
