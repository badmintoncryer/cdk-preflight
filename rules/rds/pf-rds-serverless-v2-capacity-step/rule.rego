package cdk_preflight

import rego.v1

_pf_rdsstep_bad(n) if {
	f := n * 2
	f != round(f)
}

violation contains make_diag_full("pf-rds-serverless-v2-capacity-step", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v is not a multiple of 0.5 (\"Serverless v2 capacity value 0.3 is not valid. It must be a multiple of 0.5.\")", [n]),
	"Round the capacity to a multiple of 0.5",
	"https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.setting-capacity.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	_pf_rdsstep_bad(n)
}

violation contains make_diag_full("pf-rds-serverless-v2-capacity-step", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MaxCapacity",
	sprintf("MaxCapacity %v is not a multiple of 0.5 (\"Serverless v2 capacity value 0.3 is not valid. It must be a multiple of 0.5.\")", [n]),
	"Round the capacity to a multiple of 0.5",
	"https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.setting-capacity.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	_pf_rdsstep_bad(n)
}
