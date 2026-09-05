package cdk_preflight

import rego.v1

_pf_efsmtaz_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateMountTarget.html"

_pf_efsmtaz_fix := "Give each mount target of a file system a subnet in a different Availability Zone, and put the mount target of a One Zone file system in the zone named by AvailabilityZoneName"

violation contains make_diag_full("pf-efs-mount-target-availability-zone", "ERROR", name,
	"Properties.SubnetId",
	sprintf("mount target '%s' of the same file system already covers %s; a file system takes one mount target per Availability Zone and the deployment fails with MountTargetConflict", [other, az]),
	_pf_efsmtaz_fix, _pf_efsmtaz_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	fs := _pf_efslib_fs_of(name)
	az := _pf_efslib_subnet_az(name)
	some other in resources_of_type("AWS::EFS::MountTarget")
	other != name
	_pf_efslib_fs_of(other) == fs
	_pf_efslib_subnet_az(other) == az
	other < name
}

violation contains make_diag_full("pf-efs-mount-target-availability-zone", "ERROR", name,
	"Properties.SubnetId",
	sprintf("the subnet is in %s but the One Zone file system lives in %s; CreateMountTarget fails with \"File System Availability Zone does not match.\"", [az, fsaz]),
	_pf_efsmtaz_fix, _pf_efsmtaz_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	az := _pf_efslib_subnet_az(name)
	fsaz := resolve(_pf_efslib_fs_of(name), "Properties.AvailabilityZoneName")
	is_string(fsaz)
	not input.resources[fsaz]
	fsaz != az
}
