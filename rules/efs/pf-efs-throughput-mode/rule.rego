package cdk_preflight

import rego.v1

_pf_efstm_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateFileSystem.html"

_pf_efstm_fix := "Set ThroughputMode: provisioned together with ProvisionedThroughputInMibps (1-3414), or drop the number and use bursting / elastic"

_pf_efstm_mode(name) := m if {
	m := resolve(name, "Properties.ThroughputMode")
	is_string(m)
}

_pf_efstm_mode(name) := "bursting" if _pf_efslib_absent(name, "ThroughputMode")

violation contains make_diag_full("pf-efs-throughput-mode", "ERROR", name,
	"Properties.ProvisionedThroughputInMibps",
	"ThroughputMode is provisioned but ProvisionedThroughputInMibps is missing; CreateFileSystem fails with \"Provisioned throughput must be set for file systems that use provisioned throughput mode.\"",
	_pf_efstm_fix, _pf_efstm_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	resolve(name, "Properties.ThroughputMode") == "provisioned"
	_pf_efslib_absent(name, "ProvisionedThroughputInMibps")
}

violation contains make_diag_full("pf-efs-throughput-mode", "ERROR", name,
	"Properties.ProvisionedThroughputInMibps",
	sprintf("ProvisionedThroughputInMibps is set but ThroughputMode is %s; CreateFileSystem fails with \"Provisioned throughput can't be set for file systems that use %s throughput mode.\"", [m, m]),
	_pf_efstm_fix, _pf_efstm_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	not _pf_efslib_absent(name, "ProvisionedThroughputInMibps")
	m := _pf_efstm_mode(name)
	m != "provisioned"
}

violation contains make_diag_full("pf-efs-throughput-mode", "ERROR", name,
	"Properties.ProvisionedThroughputInMibps",
	sprintf("ProvisionedThroughputInMibps is %v; the documented ceiling is 3414 MiBps and most regions cap lower (CreateFileSystem fails with ThroughputLimitExceeded)", [v]),
	_pf_efstm_fix, _pf_efstm_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	v := to_number(resolve(name, "Properties.ProvisionedThroughputInMibps"))
	v > 3414
}
