package cdk_preflight

import rego.v1

# Denylist: the families whose list-instance-type-details InstanceRole holds
# no "master" entry (all 231 OpenSearch_2.19 types, us-east-1 2026-09-24).
# A family AWS adds later is a miss, never a false positive.
_pf_osmc_never_master := {"i7i", "i8g", "i8ge", "oi2", "om2", "or1", "or2", "r7gd", "r8gd", "ultrawarm1"}

violation contains make_diag_full("pf-opensearch-master-type-master-capable", "ERROR", name,
	"Properties.ClusterConfig.DedicatedMasterType",
	sprintf("%v cannot hold the master role; CreateDomain answers \"Invalid instance type for master nodes: %v\"", [t, t]),
	"Pick a master-capable family (m6g / m7g / r6g / c6g / m5 / t3 and the like)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html") if {
	some name in _pf_os_domains
	t := _pf_os_opt(name, "ClusterConfig", "DedicatedMasterType")
	_pf_os_family(t) in _pf_osmc_never_master
}
