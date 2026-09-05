package cdk_preflight

import rego.v1

_pf_efsmtnw_url := "https://docs.aws.amazon.com/efs/latest/ug/limits.html"

_pf_efsmtnw_fix := "Keep SecurityGroups at five or fewer, create them in the VPC of the subnet, and mount a file system from one VPC only"

# The registry schema allows 100 security groups; the service quota is five.
violation contains make_diag_full("pf-efs-mount-target-network", "ERROR", name,
	"Properties.SecurityGroups",
	sprintf("%d security groups are attached; a mount target network interface accepts five and the deployment fails with \"The maximum number of security groups per interface has been reached.\"", [count(sgs)]),
	_pf_efsmtnw_fix, _pf_efsmtnw_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	sgs := resolve(name, "Properties.SecurityGroups")
	is_array(sgs)
	count(sgs) > 5
}

violation contains make_diag_full("pf-efs-mount-target-network", "ERROR", name,
	"Properties.SecurityGroups",
	sprintf("security group '%s' is in VPC '%s' but the subnet is in VPC '%s'; CreateMountTarget fails with \"You have specified two resources that belong to different networks.\"", [sg, sgvpc, subvpc]),
	_pf_efsmtnw_fix, _pf_efsmtnw_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	subvpc := _pf_efslib_vpc_of(_pf_efslib_subnet_of(name))
	sgs := resolve(name, "Properties.SecurityGroups")
	is_array(sgs)
	some sg in sgs
	sg in resources_of_type("AWS::EC2::SecurityGroup")
	sgvpc := _pf_efslib_vpc_of(sg)
	sgvpc != subvpc
}

violation contains make_diag_full("pf-efs-mount-target-network", "ERROR", name,
	"Properties.SubnetId",
	sprintf("mount target '%s' of the same file system is in VPC '%s' but this subnet is in VPC '%s'; a file system serves one VPC and the deployment fails with \"requested subnet for new mount target is not in the same VPC as existing mount targets\"", [other, othervpc, vpc]),
	_pf_efsmtnw_fix, _pf_efsmtnw_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	fs := _pf_efslib_fs_of(name)
	vpc := _pf_efslib_vpc_of(_pf_efslib_subnet_of(name))
	some other in resources_of_type("AWS::EFS::MountTarget")
	other != name
	_pf_efslib_fs_of(other) == fs
	othervpc := _pf_efslib_vpc_of(_pf_efslib_subnet_of(other))
	othervpc != vpc
	other < name
}
