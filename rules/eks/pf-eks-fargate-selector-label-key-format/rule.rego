package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-fargate-selector-label-key-format", "ERROR", name,
	sprintf("Properties.Selectors.%v.Labels.%v.Key", [s.index, i]),
	sprintf("selector label key %v is not a Kubernetes qualified name (\"Selector label provided is invalid.\")", [k]),
	"Use an optional DNS-subdomain prefix plus a name of letters, digits, '-', '_' and '.'",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-fargateprofile-label.html") if {
	some name in resources_of_type("AWS::EKS::FargateProfile")
	some s in flatten_list(name, "Properties.Selectors")
	labels := _pf_ekslib_oget(s.value, "Labels")
	is_array(labels)
	some i, l in labels
	k := _pf_ekslib_oget(l, "Key")
	_pf_ekslib_lit(k)
	not _pf_ekslib_qualified_name(k)
}
