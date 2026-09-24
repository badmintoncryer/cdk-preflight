package cdk_preflight

import rego.v1

# Absent and empty both reach the service as no namespaces at all.
violation contains make_diag_full("pf-eks-accessentry-scope-namespace-requires-namespaces", "ERROR", name,
	sprintf("Properties.AccessPolicies.%v.AccessScope", [ap.index]),
	"AccessScope.Type is namespace but no Namespaces are given (\"At least 1 namespace must be provided if the type is set as namespace\")",
	"List the namespaces the policy applies to, or set AccessScope.Type to cluster",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-accessentry-accessscope.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	some ap in flatten_list(name, "Properties.AccessPolicies")
	sc := _pf_ekslib_oget(ap.value, "AccessScope")
	_pf_ekslib_oget(sc, "Type") == "namespace"
	_pf_aens_empty(sc)
}

_pf_aens_empty(sc) if not _pf_ekslib_ohas(sc, "Namespaces")

_pf_aens_empty(sc) if count(_pf_ekslib_oget(sc, "Namespaces")) == 0
