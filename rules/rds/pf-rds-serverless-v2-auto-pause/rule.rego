package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-serverless-v2-auto-pause", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.SecondsUntilAutoPause",
	sprintf("SecondsUntilAutoPause is set with MinCapacity %v (\"SecondsUntilAutoPause can only be specified when minimum capacity is 0.\")", [n]),
	"Set MinCapacity to 0, or drop SecondsUntilAutoPause",
	"https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.setting-capacity.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	resolve(name, "Properties.ServerlessV2ScalingConfiguration.SecondsUntilAutoPause")
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	n != 0
}
