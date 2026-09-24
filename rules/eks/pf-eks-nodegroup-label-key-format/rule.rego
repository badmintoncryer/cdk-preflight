package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-label-key-format", "ERROR", name,
	"Properties.Labels",
	sprintf("label key %v is not a Kubernetes qualified name (\"field must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character\")", [k]),
	"Use an optional DNS-subdomain prefix plus a name of letters, digits, '-', '_' and '.'",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	labels := _pf_ekslib_get(name, "Labels")
	is_object(labels)
	some k, _ in labels
	not startswith(k, "__")
	not _pf_ekslib_qualified_name(k)
}
