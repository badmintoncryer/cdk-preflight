package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-network-policy-allow-from-public-required", "ERROR", name,
	sprintf("%v.AllowFromPublic", [p]),
	"the network policy block has no AllowFromPublic; CreateSecurityPolicy answers \"Policy json is invalid, error: [$[0].AllowFromPublic: is missing but it is required]\"",
	"Add AllowFromPublic (true for public access, false plus SourceVPCEs or SourceServices for private)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html") if {
	some name in _pf_aoss_net
	some [p, b] in _pf_aoss_blocks_at(name)
	object.get(b, "AllowFromPublic", "__pf_absent") == "__pf_absent"
}
