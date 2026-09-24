package cdk_preflight

import rego.v1

# Allowlist, hence WARN: the set is every family whose OpenSearch_2.19
# describe-instance-type-limits answers StorageTypes ebs with no instance
# entry (us-east-1, 2026-09-25, all 231 types). A family AWS adds later is
# absent from the set and would read as "EBS not required" - silent - but a
# family that gains an instance store would read as a violation, so this
# warns rather than errors. i2 and r3 offer both and are in neither this set
# nor _pf_os_instance_store_families.
_pf_osebr_ebs_only := {"c4", "c5", "c6g", "c7g", "c7i", "c8g", "m4", "m5", "m6g", "m7g", "m7i", "m8g", "om2", "or1", "or2", "r4", "r5", "r6g", "r7g", "r7i", "r8g", "t2", "t3"}

violation contains make_diag_full("pf-opensearch-ebs-required-for-ebs-only-type", "WARN", name,
	"Properties.EBSOptions.EBSEnabled",
	sprintf("%v has no instance store, so the domain needs an EBS volume; CreateDomain answers \"EBS storage must be selected for %v\"", [t, t]),
	"Set EBSOptions.EBSEnabled to true (with VolumeType and VolumeSize), or pick an instance-store family",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html") if {
	some name in _pf_os_domains
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) in _pf_osebr_ebs_only
	not _pf_os_on(name, "EBSOptions", "EBSEnabled")
}
