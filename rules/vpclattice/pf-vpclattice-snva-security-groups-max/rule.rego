package cdk_preflight

import rego.v1

# The schema has no maxItems on SecurityGroupIds, but the association takes at
# most 5 (a non-adjustable quota; "... at 'securityGroupIds' failed to satisfy
# constraint: Member must have length less than or equal to 5").
violation contains make_diag_full("pf-vpclattice-snva-security-groups-max", "ERROR", name,
	"Properties.SecurityGroupIds",
	sprintf("SecurityGroupIds lists %d security groups; the create fails with \"Member must have length less than or equal to 5\"", [n]),
	"Attach at most 5 security groups to the association",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/quotas.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	_pf_countable_list(name, "Properties.SecurityGroupIds")
	n := count(flatten_list(name, "Properties.SecurityGroupIds"))
	n > 5
}
