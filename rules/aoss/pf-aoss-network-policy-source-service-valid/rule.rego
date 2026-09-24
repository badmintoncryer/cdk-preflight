package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-network-policy-source-service-valid", "ERROR", name,
	sprintf("%v.SourceServices", [p]),
	sprintf("SourceServices %v is not a supported service principal; CreateSecurityPolicy answers \"Invalid SourceServices: [%v]\"", [svc, svc]),
	"bedrock.amazonaws.com is the only value SourceServices accepts; use SourceVPCEs for anything else",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html") if {
	some name in _pf_aoss_net
	some [p, b] in _pf_aoss_blocks_at(name)
	some svc in _pf_aoss_strings(object.get(b, "SourceServices", []))
	svc != "bedrock.amazonaws.com"
}
