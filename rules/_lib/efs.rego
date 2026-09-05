package cdk_preflight

import rego.v1

# Shared helpers for the EFS rules (rules/efs/pf-efs-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# [partition, service, region, account, resource...] of a literal ARN.
_pf_efslib_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

_pf_efslib_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

# The file system resource a mount target / access point points at, when it is
# declared in the same template (Ref or Fn::GetAtt both resolve to the id).
_pf_efslib_fs_of(name) := fs if {
	fs := resolve(name, "Properties.FileSystemId")
	fs in resources_of_type("AWS::EFS::FileSystem")
}

# The subnet a mount target uses, when the subnet is in the same template.
_pf_efslib_subnet_of(name) := sub if {
	sub := resolve(name, "Properties.SubnetId")
	sub in resources_of_type("AWS::EC2::Subnet")
}

# Availability zone of that subnet, when it is written as a literal.
_pf_efslib_subnet_az(name) := az if {
	az := resolve(_pf_efslib_subnet_of(name), "Properties.AvailabilityZone")
	is_string(az)
	not input.resources[az]
}

_pf_efslib_vpc_of(res) := vpc if {
	vpc := resolve(res, "Properties.VpcId")
	vpc in resources_of_type("AWS::EC2::VPC")
}

# ponytail: IPv4 only — the engine has no net.cidr_* builtins and an Ipv6Address
# outside the subnet is rarer than a hand-picked IPv4. IPv6 addresses are skipped.
# IPv4 dotted quad as a number; undefined for anything else.
_pf_efslib_ip(s) := n if {
	is_string(s)
	parts := split(s, ".")
	count(parts) == 4
	a := to_number(parts[0])
	b := to_number(parts[1])
	c := to_number(parts[2])
	d := to_number(parts[3])
	n := (((a * 16777216) + (b * 65536)) + (c * 256)) + d
}

# [network number, block size] of an IPv4 CIDR; undefined for anything else.
_pf_efslib_cidr(s) := [base, size] if {
	is_string(s)
	parts := split(s, "/")
	count(parts) == 2
	base := _pf_efslib_ip(parts[0])
	prefix := to_number(parts[1])
	prefix >= 0
	prefix <= 32
	size := bits.lsh(1, 32 - prefix)
}

_pf_efslib_in_cidr(ip, cidr) if {
	[base, size] := _pf_efslib_cidr(cidr)
	n := _pf_efslib_ip(ip)
	floor(n / size) == floor(base / size)
}
