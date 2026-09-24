package cdk_preflight

import rego.v1

# 10 GiB is the floor every instance type shares (describe-instance-type-limits
# MinimumVolumeSize over all 231 OpenSearch_2.19 types, us-east-1 2026-09-25).
# The or1 / or2 families start at 20 and the ceiling is per-type; neither is
# here, so this only ever flags a size no type accepts.

violation contains make_diag_full("pf-opensearch-ebs-volume-size-min", "ERROR", name,
	"Properties.EBSOptions.VolumeSize",
	sprintf("the volume asks for %v GiB but no instance type takes less than 10; CreateDomain answers \"Volume size must be between 10 and ...\"", [size]),
	"Raise VolumeSize to at least 10 GiB (20 on the or1 / or2 families; the upper end depends on the instance type)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "EBSOptions", "EBSEnabled")
	size := _pf_os_num(_pf_os_opt(name, "EBSOptions", "VolumeSize"))
	size < 10
}
