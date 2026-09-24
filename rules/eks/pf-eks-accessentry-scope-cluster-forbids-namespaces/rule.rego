package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-accessentry-scope-cluster-forbids-namespaces", "ERROR", name,
	sprintf("Properties.AccessPolicies.%v.AccessScope.Namespaces", [ap.index]),
	"AccessScope.Type is cluster, so Namespaces cannot be set (\"accessScope should not include namespaces if the type is not set as namespace\")",
	"Drop Namespaces, or set AccessScope.Type to namespace",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-accessentry-accessscope.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	some ap in flatten_list(name, "Properties.AccessPolicies")
	sc := _pf_ekslib_oget(ap.value, "AccessScope")
	_pf_ekslib_oget(sc, "Type") == "cluster"
	count(_pf_ekslib_oget(sc, "Namespaces")) > 0
}
