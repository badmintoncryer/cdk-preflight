package cdk_preflight

import rego.v1

_pf_nepstep_bad(n) if {
	f := n * 2
	f != round(f)
}

_pf_nepstep_keys := {"MinCapacity", "MaxCapacity"}

violation contains make_diag_full("pf-neptune-serverless-half-step", "ERROR", name,
	sprintf("Properties.ServerlessScalingConfiguration.%s", [k]),
	sprintf("%s %v is not a multiple of 0.5 NCU (\"Serverless v2 capacity value 4.3 is not valid. It must be a multiple of 0.5.\")", [k, n]),
	"Round the capacity to a multiple of 0.5",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster-serverlessscalingconfiguration.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	some k in _pf_nepstep_keys
	n := to_number(resolve(name, sprintf("Properties.ServerlessScalingConfiguration.%s", [k])))
	_pf_nepstep_bad(n)
}
