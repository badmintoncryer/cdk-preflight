package cdk_preflight

import rego.v1

_pf_gfnac(name) := nac if {
	nac := object.get(_pf_grafana_props(name), "NetworkAccessControl", {})
	is_object(nac)
}

# The registry schema carries no pattern here, and the doc only says prefix list
# ids "have the format pl-1a2b3c4d". The service quotes the pattern verbatim, and
# a well formed id that does not exist is a different sentence (Prefix List Ids
# [...] are invalid), so the two failures stay distinguishable.
violation contains make_diag_full("pf-grafana-ws-nac-id-prefix", "ERROR", name,
	"Properties.NetworkAccessControl.PrefixListIds",
	sprintf("PrefixListIds entry \"%v\" is not a prefix-list id; CreateWorkspace fails with \"The Prefix List Id should satisfy the pattern ^pl-[a-z0-9_]{1,32}$.\"", [id]),
	"Pass the prefix list's Id (pl-...), not its name or its ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-grafana-workspace-networkaccesscontrol.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	some id in _pf_grafana_strings(_pf_gfnac(name), "PrefixListIds")
	not regex.match(`^pl-[a-z0-9_]{1,32}$`, id)
}

# VpceIds is quoted with its own, different pattern: hexadecimal only, where the
# prefix list's admits letters and underscores. The doc calls both "the format
# vpce-1a2b3c4d" and says nothing about the charset; this one was measured on
# 2026-09-27, so the two bodies do not share a pattern.
violation contains make_diag_full("pf-grafana-ws-nac-id-prefix", "ERROR", name,
	"Properties.NetworkAccessControl.VpceIds",
	sprintf("VpceIds entry \"%v\" is not a VPC endpoint id; CreateWorkspace fails with \"The VPC endpoint should satisfy the pattern ^vpce-[0-9a-f]{1,32}$.\"", [id]),
	"Pass the interface endpoint's Id (vpce-...), not its name or its DNS entry",
	"DOCNAC") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	some id in _pf_grafana_strings(_pf_gfnac(name), "VpceIds")
	not regex.match(`^vpce-[0-9a-f]{1,32}$`, id)
}
