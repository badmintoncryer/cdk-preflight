package cdk_preflight

import rego.v1

_pf_efspm_url := "https://docs.aws.amazon.com/efs/latest/ug/performance.html"

_pf_efspm_fix := "Drop PerformanceMode (generalPurpose is the default and the recommended mode) or drop AvailabilityZoneName / elastic throughput"

violation contains make_diag_full("pf-efs-performance-mode", "ERROR", name,
	"Properties.PerformanceMode",
	"PerformanceMode is maxIO and AvailabilityZoneName makes this a One Zone file system; CreateFileSystem fails with \"Unsupported performance mode provided.\"",
	_pf_efspm_fix, _pf_efspm_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	resolve(name, "Properties.PerformanceMode") == "maxIO"
	not _pf_efslib_absent(name, "AvailabilityZoneName")
}

violation contains make_diag_full("pf-efs-performance-mode", "ERROR", name,
	"Properties.PerformanceMode",
	"PerformanceMode is maxIO and ThroughputMode is elastic; CreateFileSystem fails with \"Elastic throughput is not available for file systems using MaxIO performance mode.\"",
	_pf_efspm_fix, _pf_efspm_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	resolve(name, "Properties.PerformanceMode") == "maxIO"
	resolve(name, "Properties.ThroughputMode") == "elastic"
}
