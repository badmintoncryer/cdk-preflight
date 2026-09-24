package cdk_preflight

import rego.v1

# Only the two types the CloudFormation page names are judged. Whether
# FARGATE_LINUX / HYBRID_LINUX / EC2 refuse groups too was not measured.
violation contains make_diag_full("pf-eks-accessentry-node-type-forbids-groups", "ERROR", name,
	"Properties.KubernetesGroups",
	sprintf("a %v access entry cannot carry KubernetesGroups (\"The specified kubernetesGroups is invalid: setting kubernetesGroups is not allowed when the type is \\\"%v\\\"\")", [t, t]),
	"Drop KubernetesGroups, or use type STANDARD - EKS grants node permissions itself",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-accessentry.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	t := resolve(name, "Properties.Type")
	t in {"EC2_LINUX", "EC2_WINDOWS"}
	count(flatten_list(name, "Properties.KubernetesGroups")) > 0
}
