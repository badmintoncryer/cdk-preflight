package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-label-reserved-prefix", "ERROR", name,
	"Properties.Labels",
	sprintf("label key %v uses a prefix EKS reserves (\"Label cannot start with reserved prefixes [kubernetes.io/, k8s.io/, eks.amazonaws.com/]\")", [k]),
	"Move the label under a prefix of your own, e.g. example.com/<name>",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	labels := _pf_ekslib_get(name, "Labels")
	is_object(labels)
	some k, _ in labels
	some p in {"kubernetes.io/", "k8s.io/", "eks.amazonaws.com/"}
	startswith(k, p)
}
