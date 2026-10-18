package cdk_preflight

import rego.v1

# CreateListener rejects a second listener on a port the service already
# listens on ("Port 443 is occupied"). The protocol default port (80 / 443) is
# not filled in. Only resources in one template that name the same ServiceIdentifier (the
# same logical id or the same literal) are compared, and only explicit values.
violation contains make_diag_full("pf-vpclattice-listener-port-duplicate", "ERROR", name,
	"Properties.Port",
	sprintf("Listener Port %v is already used by '%s' under the same ServiceIdentifier; the create fails with \"Port 443 is occupied\"", [v, other]),
	"Give each listener of the service its own Port",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateListener.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	p := resolve(name, "Properties.ServiceIdentifier")
	is_string(p)
	v := resolve(name, "Properties.Port")
	_pf_vpcl_lit(v)
	some other in resources_of_type("AWS::VpcLattice::Listener")
	other < name
	resolve(other, "Properties.ServiceIdentifier") == p
	resolve(other, "Properties.Port") == v
}
