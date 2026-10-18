package cdk_preflight

import rego.v1

# An IP target group registers addresses of one family, IpAddressType
# (default IPV4). RegisterTargets rejects the other family ("IP address for
# target 2001:db8::10 is invalid itself or invalid for the target group ip
# address type IPV4").
_pf_vpcltif_wrong("IPV4", id) if contains(id, ":")

_pf_vpcltif_wrong("IPV6", id) if regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`, id)

violation contains make_diag_full("pf-vpclattice-tg-target-ip-family", "ERROR", name,
	sprintf("Properties.Targets.%d.Id", [t.index]),
	sprintf("Target '%s' is not an %s address; RegisterTargets fails with \"invalid for the target group ip address type %s\"", [id, fam, fam]),
	"Register addresses of the target group IpAddressType, or change IpAddressType",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-groups.html") if {
	some name in _pf_vpcl_tgs_of("IP")
	fam := _pf_vpcl_str(name, "Properties.Config.IpAddressType", "IPV4")
	some t in flatten_list(name, "Properties.Targets")
	id := _pf_vpcl_target_id(t)
	_pf_vpcltif_wrong(fam, id)
}
