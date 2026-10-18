package cdk_preflight

import rego.v1

# Name is not the primary identifier, so the schema says nothing about
# uniqueness, but CreateListener rejects a name the service already has
# ("Listener with name ... already exists in svc-... service"). Only resources in one template that name the same ServiceIdentifier (the
# same logical id or the same literal) are compared, and only explicit values.
violation contains make_diag_full("pf-vpclattice-listener-name-duplicate", "ERROR", name,
	"Properties.Name",
	sprintf("Listener name %v is already used by '%s' under the same ServiceIdentifier; the create fails with \"Listener with name ... already exists in svc-... service.\"", [v, other]),
	"Give each listener of the service its own Name",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateListener.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	p := resolve(name, "Properties.ServiceIdentifier")
	is_string(p)
	v := resolve(name, "Properties.Name")
	_pf_vpcl_lit(v)
	some other in resources_of_type("AWS::VpcLattice::Listener")
	other < name
	resolve(other, "Properties.ServiceIdentifier") == p
	resolve(other, "Properties.Name") == v
}
