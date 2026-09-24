package cdk_preflight

import rego.v1

# Denylist: every master-capable family that is not Graviton-based
# (list-instance-type-details, all 231 OpenSearch_2.19 types, us-east-1
# 2026-09-24). A Graviton family AWS adds later is simply not flagged.
_pf_osog_x86_master := {"c4", "c5", "c7i", "i2", "i3", "i4i", "m4", "m5", "m7i", "r3", "r4", "r5", "r7i", "t2", "t3"}

violation contains make_diag_full("pf-opensearch-or1-master-graviton", "ERROR", name,
	"Properties.ClusterConfig.DedicatedMasterType",
	sprintf("an OR1 data tier with %v masters; CreateDomain answers \"Graviton-based master nodes are required for OR1 instance family.\"", [t]),
	"Use a Graviton master type (m6g / m7g / r6g / c6g and the like)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/or1.html") if {
	some name in _pf_os_domains
	_pf_os_family(_pf_os_opt(name, "ClusterConfig", "InstanceType")) == "or1"
	t := _pf_os_opt(name, "ClusterConfig", "DedicatedMasterType")
	_pf_os_family(t) in _pf_osog_x86_master
}
