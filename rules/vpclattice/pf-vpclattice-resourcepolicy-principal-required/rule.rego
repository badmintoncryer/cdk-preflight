package cdk_preflight

import rego.v1

# A resource policy is a resource-based policy, so each statement must say who it
# applies to. PutResourcePolicy rejects a statement without Principal
# ("A Principal is required"). A statement with NotPrincipal is left alone, and so is
# a statement or document that is an intrinsic.
violation contains make_diag_full("pf-vpclattice-resourcepolicy-principal-required", "ERROR", name,
	sprintf("Properties.Policy.Statement.%d", [i]),
	"The statement has no Principal; PutResourcePolicy fails with \"A Principal is required\"",
	"Add Principal to the statement (for example \"*\" or {\"AWS\": \"<account or role ARN>\"})",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_PutResourcePolicy.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourcePolicy")
	some [i, s] in _pf_vpcl_stmts(name)
	is_object(s)
	object.get(s, "Principal", "__pf_absent") == "__pf_absent"
	object.get(s, "NotPrincipal", "__pf_absent") == "__pf_absent"
}
