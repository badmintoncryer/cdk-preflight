package cdk_preflight

import rego.v1

# The association id is service-generated, so CloudFormation's own duplicate
# primary-id check does not catch this - EKS does.
violation contains make_diag_full("pf-eks-podidentity-duplicate", "ERROR", name,
	"Properties.ServiceAccount",
	sprintf("%v already associates an IAM role with the same namespace and service account on this cluster (\"Association already exists\")", [a]),
	"Keep one association per service account; point it at a role that carries every permission the pods need",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-podidentityassociation.html") if {
	some a in resources_of_type("AWS::EKS::PodIdentityAssociation")
	some b in resources_of_type("AWS::EKS::PodIdentityAssociation")
	a < b
	resolve(a, "Properties.ClusterName") == resolve(b, "Properties.ClusterName")
	resolve(a, "Properties.Namespace") == resolve(b, "Properties.Namespace")
	resolve(a, "Properties.ServiceAccount") == resolve(b, "Properties.ServiceAccount")
	name := b
}
