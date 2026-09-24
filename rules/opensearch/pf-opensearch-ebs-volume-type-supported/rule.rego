package cdk_preflight

import rego.v1

# Denylist: every family whose OpenSearch_2.19 StorageTypes hold ebs entries
# but no gp2 one (describe-instance-type-limits over all 231 types, us-east-1
# 2026-09-25). A family AWS adds later is simply not flagged.
_pf_osvt_no_gp2 := {"c7g", "c7i", "c8g", "m7g", "m7i", "m8g", "om2", "or1", "or2", "r7g", "r7i", "r8g"}

violation contains make_diag_full("pf-opensearch-ebs-volume-type-supported", "ERROR", name,
	"Properties.EBSOptions.VolumeType",
	sprintf("%v does not offer gp2 storage; CreateDomain answers \"EBS volume-types :[io1, gp3] must be selected for %v\"", [t, t]),
	"Use gp3 (with Iops and Throughput) or io1 on this family",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html") if {
	some name in _pf_os_domains
	_pf_os_opt(name, "EBSOptions", "VolumeType") == "gp2"
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) in _pf_osvt_no_gp2
}
