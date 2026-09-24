package cdk_preflight

import rego.v1

# A denylist of the volume types that reject Iops, not an allowlist of the
# two that take it: a volume type AWS adds later is then a miss, never a
# false positive.
_pf_osiop_no_iops := {"standard", "gp2"}

violation contains make_diag_full("pf-opensearch-ebs-iops-only-gp3-io1", "ERROR", name,
	"Properties.EBSOptions.Iops",
	sprintf("Iops is set on a %v volume; CreateDomain answers \"IOPS is only valid when volume type is io1 or gp3.\"", [vt]),
	"Drop Iops, or switch the volume to gp3 or io1",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-ebsoptions.html") if {
	some name in _pf_os_domains
	vt := _pf_os_opt(name, "EBSOptions", "VolumeType")
	vt in _pf_osiop_no_iops
	not _pf_os_missing(name, "EBSOptions", "Iops")
}
