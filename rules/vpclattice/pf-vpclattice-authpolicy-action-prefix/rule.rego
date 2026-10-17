package cdk_preflight

import rego.v1

# An auth policy decides who may call the services behind Lattice, so its
# actions come from the vpc-lattice-svcs namespace only. PutAuthPolicy rejects
# any other action ("Invalid action s3:GetObject in policy"). Only literal
# Action entries are read; "*" and NotAction are left alone.
violation contains make_diag_full("pf-vpclattice-authpolicy-action-prefix", "ERROR", name,
	sprintf("Properties.Policy.Statement.%d.Action", [i]),
	sprintf("Action '%s' is not a vpc-lattice-svcs action; PutAuthPolicy fails with \"Invalid action %s in policy\"", [a, a]),
	"Use vpc-lattice-svcs:Invoke (or vpc-lattice-svcs:Connect); grant other services in IAM policies",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/auth-policies.html") if {
	some name in resources_of_type("AWS::VpcLattice::AuthPolicy")
	some [i, s] in _pf_vpcl_stmts(name)
	is_object(s)
	some a in _pf_iamlib_list(object.get(s, "Action", null))
	is_string(a)
	a != "*"
	not startswith(lower(a), "vpc-lattice-svcs:")
}
