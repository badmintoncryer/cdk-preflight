package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-serverless-min-le-max", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v exceeds MaxCapacity %v (\"Serverless v2 minimum capacity must be less than or equal to maximum capacity\")", [mn, mx]),
	"Keep MinCapacity <= MaxCapacity",
	"https://docs.aws.amazon.com/documentdb/latest/developerguide/API_ServerlessV2ScalingConfiguration.html") if {
	some name in _pf_docdb_clusters
	mn := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	mx := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	mn > mx
}
