package cdk_preflight

import rego.v1

# Both sides are only knowable inside one template; an imported cluster leaves
# ClusterName a literal on both entries, which still compares equal.
# The access entry physical id is "<principalArn>|<clusterName>", so what
# actually stops this is CloudFormation own duplicate primary-id check, not
# the ResourceInUseException CreateAccessEntry raises outside CloudFormation.
violation contains make_diag_full("pf-eks-accessentry-principal-arn-duplicate", "ERROR", name,
	"Properties.PrincipalArn",
	sprintf("%v already holds an access entry for the same principal on this cluster (\"<principalArn>|<clusterName> already exists in stack\")", [a]),
	"Declare one access entry per principal and put every group and policy on it",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some a in resources_of_type("AWS::EKS::AccessEntry")
	some b in resources_of_type("AWS::EKS::AccessEntry")
	a < b
	resolve(a, "Properties.ClusterName") == resolve(b, "Properties.ClusterName")
	resolve(a, "Properties.PrincipalArn") == resolve(b, "Properties.PrincipalArn")
	name := b
}
