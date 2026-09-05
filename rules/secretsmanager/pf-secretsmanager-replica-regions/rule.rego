package cdk_preflight

import rego.v1

_pf_smrr_url := "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html"

_pf_smrr_fix := "List only regions other than the deploy region (a secret cannot replicate to itself)"

_pf_smrr_entries contains [name, i] if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	some e in flatten_list(name, "Properties.ReplicaRegions")
	i := e.index
}

# Region comparison needs the deploy region (enforce mode only).
violation contains make_diag_full("pf-secretsmanager-replica-regions", "ERROR", name,
	sprintf("Properties.ReplicaRegions.%d.Region", [i]),
	sprintf("replica region '%s' is the region this secret deploys to; CreateSecret fails with \"Invalid replica region.\"", [r]),
	_pf_smrr_fix, _pf_smrr_url) if {
	region := data.cdk_preflight.deploy_region
	some [name, i] in _pf_smrr_entries
	r := resolve(name, sprintf("Properties.ReplicaRegions.%d.Region", [i]))
	r == region
}

violation contains make_diag_full("pf-secretsmanager-replica-regions", "ERROR", name,
	sprintf("Properties.ReplicaRegions.%d.Region", [i]),
	sprintf("'%s' is not an AWS region name; CreateSecret fails with \"Invalid replica region.\"", [r]),
	_pf_smrr_fix, _pf_smrr_url) if {
	some [name, i] in _pf_smrr_entries
	r := resolve(name, sprintf("Properties.ReplicaRegions.%d.Region", [i]))
	is_string(r)
	not regex.match("^[a-z]{2}(-gov)?(-iso[a-z]?)?-[a-z]+-[0-9]$", r)
}
