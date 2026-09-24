package cdk_preflight

import rego.v1

# Both sides are only knowable inside one template: an imported cluster leaves
# ClusterName a literal on both add-ons, which still compares equal, so the
# rule works for a literal cluster name too.
violation contains make_diag_full("pf-eks-addon-duplicate-per-cluster", "ERROR", b,
	"Properties.AddonName",
	sprintf("add-on %v is already installed on the same cluster by %v (\"Addon already exists.\")", [an, a]),
	"Declare each add-on once per cluster",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-addon.html") if {
	some a in resources_of_type("AWS::EKS::Addon")
	some b in resources_of_type("AWS::EKS::Addon")
	a < b
	resolve(a, "Properties.ClusterName") == resolve(b, "Properties.ClusterName")
	an := resolve(a, "Properties.AddonName")
	an == resolve(b, "Properties.AddonName")
}
