package cdk_preflight

import rego.v1

_pf_rdssv2_url := "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.setting-capacity.html"

violation contains make_diag_full("pf-rds-serverless-v2-capacity", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v exceeds MaxCapacity %v (\"minimum capacity must be less than or equal to maximum capacity\")", [mn, mx]),
	"Keep MinCapacity <= MaxCapacity",
	_pf_rdssv2_url) if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	mn := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	mx := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	mn > mx
}

violation contains make_diag_full("pf-rds-serverless-v2-capacity", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MaxCapacity",
	sprintf("MaxCapacity %v is above 256 ACUs (\"The valid scaling range for this cluster is 0.0 to 256.0.\")", [mx]),
	"Use at most 256 ACUs",
	_pf_rdssv2_url) if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	mx := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	mx > 256
}
