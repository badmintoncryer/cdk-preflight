package cdk_preflight

import rego.v1

# A denylist of the EBS types standby rejects, not an allowlist of the two it
# takes: a volume type AWS adds later is then a miss, never a false positive.
_pf_ossv_rejected := {"standard", "gp2"}

violation contains make_diag_full("pf-opensearch-standby-volume-type", "ERROR", name,
	"Properties.EBSOptions.VolumeType",
	sprintf("standby on a %v volume; CreateDomain answers \"Domains with standby only support the GP3 and io1 volume types of EBS storage.\"", [vt]),
	"Use gp3 (with Iops and Throughput) or io1, or drop MultiAZWithStandbyEnabled",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "MultiAZWithStandbyEnabled")
	vt := _pf_os_opt(name, "EBSOptions", "VolumeType")
	vt in _pf_ossv_rejected
}
