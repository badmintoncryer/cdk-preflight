package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-network-policy-private-source-required", "ERROR", name,
	sprintf("%v.SourceVPCEs", [p]),
	"the network policy block sets AllowFromPublic to false but names neither SourceVPCEs nor SourceServices; CreateSecurityPolicy answers \"Policy json is invalid, error: [$[0].AllowFromPublic: must be a constant value true]\"",
	"Add SourceVPCEs (managed VPC endpoint ids) or SourceServices, or set AllowFromPublic to true",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html") if {
	some name in _pf_aoss_net
	some [p, b] in _pf_aoss_blocks_at(name)
	object.get(b, "AllowFromPublic", null) == false
	object.get(b, "SourceVPCEs", "__pf_absent") == "__pf_absent"
	object.get(b, "SourceServices", "__pf_absent") == "__pf_absent"
}
