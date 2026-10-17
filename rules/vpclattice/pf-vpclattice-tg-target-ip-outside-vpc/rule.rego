package cdk_preflight

import rego.v1

# RegisterTargets accepts only addresses inside the target group VPC ("Target:
# 172.32.0.10 has an invalid IP/port or it is not in active VPC CIDR block").
# Checked only when Config.VpcIdentifier references an AWS::EC2::VPC in the same
# template with a literal CidrBlock and no AWS::EC2::VPCCidrBlock adds another
# range to it. IPv4 targets only.
_pf_vpcltov_extra(vpc) if {
	some c in resources_of_type("AWS::EC2::VPCCidrBlock")
	resolve(c, "Properties.VpcId") == vpc
}

violation contains make_diag_full("pf-vpclattice-tg-target-ip-outside-vpc", "ERROR", name,
	sprintf("Properties.Targets.%d.Id", [t.index]),
	sprintf("Target '%s' is outside the VPC CIDR %s; RegisterTargets fails with \"not in active VPC CIDR block\"", [id, cidr]),
	"Register an address from the VPC CIDR",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-groups.html") if {
	some name in _pf_vpcl_tgs_of("IP")
	vpc := resolve(name, "Properties.Config.VpcIdentifier")
	is_string(vpc)
	vpc in resources_of_type("AWS::EC2::VPC")
	cidr := resolve(vpc, "Properties.CidrBlock")
	is_string(cidr)
	not _pf_vpcltov_extra(vpc)
	some t in flatten_list(name, "Properties.Targets")
	id := _pf_vpcl_target_id(t)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`, id)
	not _pf_ec2lib_cidr_has_ip(cidr, id)
}
