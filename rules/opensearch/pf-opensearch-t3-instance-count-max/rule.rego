package cdk_preflight

import rego.v1

# Data nodes only: CreateDomain accepted 10 data nodes plus 3 dedicated masters
# on 2026-09-24 (deleted before it finished building), so the masters do not
# count against the 10. describe-instance-type-limits answers
# MaximumInstanceCount 10 for the data role on t3.small.search.

violation contains make_diag_full("pf-opensearch-t3-instance-count-max", "ERROR", name,
	"Properties.ClusterConfig.InstanceCount",
	sprintf("%v data nodes on %v; CreateDomain answers \"Instance count should be between 1 and 10.\"", [n, t]),
	"Keep T3 data nodes at 10 or fewer, or move the data tier to another family",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html") if {
	some name in _pf_os_domains
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) == "t3"
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "InstanceCount"))
	n > 10
}
