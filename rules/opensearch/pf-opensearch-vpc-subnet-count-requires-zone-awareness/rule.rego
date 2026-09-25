package cdk_preflight

import rego.v1

# count() of the literal list rather than resolve(): a list of Refs still has a
# length, and the length is the whole question here.

violation contains make_diag_full("pf-opensearch-vpc-subnet-count-requires-zone-awareness", "ERROR", name,
	"Properties.VPCOptions.SubnetIds",
	sprintf("%v subnets without ZoneAwarenessEnabled; CreateDomain answers \"You must specify exactly one subnet.\"", [count(ids)]),
	"Set ClusterConfig.ZoneAwarenessEnabled with a ZoneAwarenessConfig, or pass a single subnet",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-vpcoptions.html") if {
	some name in _pf_os_domains
	ids := object.get(_pf_os_obj(_pf_os_at(name, "VPCOptions")), "SubnetIds", [])
	is_array(ids)
	_pf_countable_items(ids)
	count(ids) > 1
	not _pf_os_on(name, "ClusterConfig", "ZoneAwarenessEnabled")
}
