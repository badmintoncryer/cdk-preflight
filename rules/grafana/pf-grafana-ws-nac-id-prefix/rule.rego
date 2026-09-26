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
