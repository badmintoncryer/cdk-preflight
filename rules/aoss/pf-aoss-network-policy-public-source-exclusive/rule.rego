package cdk_preflight

import rego.v1

# The developer guide documents SourceVPCEs / SourceServices as what you add
# when AllowFromPublic is false, but never says the pair is exclusive. The
# server enforces it with a JSON-schema "not", and nothing below Policy is
# visible to the schema layer.

violation contains make_diag_full("pf-aoss-network-policy-public-source-exclusive", "ERROR", name,
	sprintf("%v.%v", [p, k]),
	sprintf("the network policy block sets AllowFromPublic to true and also names %v; CreateSecurityPolicy answers \"Policy json is invalid, error: [$[0].AllowFromPublic: must be a constant value false, $[0]: should not be valid to the schema \"not\" : {\"anyOf\":[{\"required\":[\"SourceVPCEs\"]},{\"required\":[\"SourceServices\"]}]}]\"", [k]),
	sprintf("Set AllowFromPublic to false to use %v, or drop it to allow public access", [k]),
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html") if {
	some name in _pf_aoss_net
	some [p, b] in _pf_aoss_blocks_at(name)
	object.get(b, "AllowFromPublic", null) == true
	some k in {"SourceVPCEs", "SourceServices"}
	object.get(b, k, "__pf_absent") != "__pf_absent"
}
