package cdk_preflight

import rego.v1

# Denylist of the volume types that reject Throughput rather than an
# allowlist holding gp3 alone, so a volume type AWS adds later is a miss
# rather than a false positive.
_pf_ostp_no_throughput := {"standard", "gp2", "io1"}

violation contains make_diag_full("pf-opensearch-ebs-throughput-only-gp3", "ERROR", name,
	"Properties.EBSOptions.Throughput",
	sprintf("Throughput is set on a %v volume; CreateDomain answers \"Throughput is only valid when volume type is GP3.\"", [vt]),
	"Drop Throughput, or switch the volume to gp3",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-ebsoptions.html") if {
	some name in _pf_os_domains
	vt := _pf_os_opt(name, "EBSOptions", "VolumeType")
	vt in _pf_ostp_no_throughput
	not _pf_os_missing(name, "EBSOptions", "Throughput")
}
