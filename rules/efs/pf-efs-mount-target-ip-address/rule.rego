package cdk_preflight

import rego.v1

_pf_efsmtip_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateMountTarget.html"

_pf_efsmtip_fix := "Pick an address from the subnet CIDR (or leave IpAddress out and let EFS choose), and only ask for IPv6 on a subnet that has an IPv6 CIDR"

violation contains make_diag_full("pf-efs-mount-target-ip-address", "ERROR", name,
	"Properties.IpAddress",
	sprintf("IpAddress %s is outside the subnet CIDR %s; CreateMountTarget fails with \"Address does not fall within the subnet's address range\"", [ip, cidr]),
	_pf_efsmtip_fix, _pf_efsmtip_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	ip := resolve(name, "Properties.IpAddress")
	cidr := resolve(_pf_efslib_subnet_of(name), "Properties.CidrBlock")
	is_string(cidr)
	_pf_efslib_ip(ip)
	not _pf_efslib_in_cidr(ip, cidr)
}

violation contains make_diag_full("pf-efs-mount-target-ip-address", "ERROR", name,
	"Properties.Ipv6Address",
	sprintf("Ipv6Address is set but IpAddressType is %s; CreateMountTarget fails with \"The provided IP address does not match the specified IpAddressType.\"", [t]),
	_pf_efsmtip_fix, _pf_efsmtip_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	not _pf_efslib_absent(name, "Ipv6Address")
	t := _pf_efsmtip_type(name)
	t == "IPV4_ONLY"
}

violation contains make_diag_full("pf-efs-mount-target-ip-address", "ERROR", name,
	"Properties.IpAddress",
	"IpAddress is set but IpAddressType is IPV6_ONLY; CreateMountTarget fails with \"The provided IP address does not match the specified IpAddressType.\"",
	_pf_efsmtip_fix, _pf_efsmtip_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	not _pf_efslib_absent(name, "IpAddress")
	_pf_efsmtip_type(name) == "IPV6_ONLY"
}

violation contains make_diag_full("pf-efs-mount-target-ip-address", "ERROR", name,
	"Properties.IpAddressType",
	sprintf("IpAddressType is %s but subnet '%s' has no IPv6 CIDR; CreateMountTarget fails with \"The provided subnet does not support IPv6-only address type.\"", [t, sub]),
	_pf_efsmtip_fix, _pf_efsmtip_url) if {
	some name in resources_of_type("AWS::EFS::MountTarget")
	t := _pf_efsmtip_type(name)
	t == "IPV6_ONLY"
	sub := _pf_efslib_subnet_of(name)
	_pf_efslib_absent(sub, "Ipv6CidrBlock")
	_pf_efslib_absent(sub, "Ipv6CidrBlocks")
	not _pf_efsmtip_assoc(sub)
}

_pf_efsmtip_assoc(sub) if {
	some a in resources_of_type("AWS::EC2::SubnetCidrBlock")
	resolve(a, "Properties.SubnetId") == sub
}

_pf_efsmtip_type(name) := t if {
	t := resolve(name, "Properties.IpAddressType")
	is_string(t)
}

_pf_efsmtip_type(name) := "IPV4_ONLY" if _pf_efslib_absent(name, "IpAddressType")
