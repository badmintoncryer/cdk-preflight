package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-neptune-serverless-min-le-max", "ERROR", name,
	"Properties.ServerlessScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v exceeds MaxCapacity %v (\"Serverless v2 minimum capacity must be less than or equal to maximum capacity\")", [mn, mx]),
	"Keep MinCapacity <= MaxCapacity",
	"https://docs.aws.amazon.com/neptune/latest/userguide/neptune-serverless-capacity-scaling.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	mn := to_number(resolve(name, "Properties.ServerlessScalingConfiguration.MinCapacity"))
	mx := to_number(resolve(name, "Properties.ServerlessScalingConfiguration.MaxCapacity"))
	mn > mx
}
