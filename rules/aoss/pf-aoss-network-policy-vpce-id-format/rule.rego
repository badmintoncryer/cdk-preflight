package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-network-policy-vpce-id-format", "ERROR", name,
	sprintf("%v.SourceVPCEs", [p]),
	sprintf("SourceVPCEs %v is not a VPC endpoint id; CreateSecurityPolicy answers \"Policy json is invalid, error: [$[0].SourceVPCEs[0]: does not match the regex pattern ^vpce-[a-zA-Z0-9]{8,20}$]\"", [v]),
	"Use the managed VPC endpoint's id (vpce-...), not a VPC id or a subnet id",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html") if {
	some name in _pf_aoss_net
	some [p, b] in _pf_aoss_blocks_at(name)
	some v in _pf_aoss_strings(object.get(b, "SourceVPCEs", []))
	not regex.match(_pf_aoss_re_vpce, v)
}
