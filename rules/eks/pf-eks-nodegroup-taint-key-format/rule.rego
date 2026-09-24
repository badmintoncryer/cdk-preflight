package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-taint-key-format", "ERROR", name,
	sprintf("Properties.Taints.%v.Key", [t.index]),
	sprintf("taint key %v is not a Kubernetes qualified name (\"invalid taint spec: a qualified name must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character\")", [k]),
	"Use an optional DNS-subdomain prefix plus a name of letters, digits, '-', '_' and '.'",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-taint.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	some t in flatten_list(name, "Properties.Taints")
	k := _pf_ekslib_oget(t.value, "Key")
	_pf_ekslib_lit(k)
	not _pf_ekslib_qualified_name(k)
}
