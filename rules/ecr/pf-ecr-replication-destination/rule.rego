package cdk_preflight

import rego.v1

_pf_ecrrep_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ReplicationDestination.html"

_pf_ecrrep_fix := "Point the destination at another region or another account; a rule cannot replicate a registry onto itself"

_pf_ecrrep_partition(region) := "aws-cn" if startswith(region, "cn-")

_pf_ecrrep_partition(region) := "aws-us-gov" if startswith(region, "us-gov-")

_pf_ecrrep_partition(region) := "aws" if {
	not startswith(region, "cn-")
	not startswith(region, "us-gov-")
}

# [name, rule index, destination index, region, registryId] of every destination.
_pf_ecrrep_dests contains [name, ri, di, region, registry] if {
	some name in resources_of_type("AWS::ECR::ReplicationConfiguration")
	rules := resolve(name, "Properties.ReplicationConfiguration.Rules")
	is_array(rules)
	some ri, rule in rules
	dests := object.get(rule, "Destinations", null)
	is_array(dests)
	some di, d in dests
	region := object.get(d, "Region", null)
	is_string(region)
	registry := object.get(d, "RegistryId", null)
}

violation contains make_diag_full("pf-ecr-replication-destination", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules[%d].Destinations[%d]", [ri, di]),
	sprintf("the destination is registry %s in '%s', which is the registry this template deploys to; PutReplicationConfiguration fails with \"Replication destination cannot be the same as the source registry\"", [registry, region]),
	_pf_ecrrep_fix, _pf_ecrrep_url) if {
	deploy := data.cdk_preflight.deploy_region
	some [name, ri, di, region, registry] in _pf_ecrrep_dests
	region == deploy
	registry == data.cdk_preflight.deploy_account
}

violation contains make_diag_full("pf-ecr-replication-destination", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules[%d].Destinations[%d].Region", [ri, di]),
	sprintf("destination region '%s' is in partition %s but the registry deploys to '%s' (%s); PutReplicationConfiguration fails with \"Invalid region '%s'\"", [region, _pf_ecrrep_partition(region), deploy, _pf_ecrrep_partition(deploy), region]),
	_pf_ecrrep_fix, _pf_ecrrep_url) if {
	deploy := data.cdk_preflight.deploy_region
	some [name, ri, di, region, _] in _pf_ecrrep_dests
	_pf_ecrrep_partition(region) != _pf_ecrrep_partition(deploy)
}
