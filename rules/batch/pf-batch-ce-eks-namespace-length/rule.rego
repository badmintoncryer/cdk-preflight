package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-namespace-length", "ERROR", name,
	"Properties.EksConfiguration.KubernetesNamespace",
	sprintf("KubernetesNamespace is %v characters (\"kubernetesNamespace must less than or equal to 63 characters\")", [count(ns)]),
	"Shorten the namespace to 63 characters or fewer",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	ns := _pf_batch_oget(_pf_batch_get(name, "EksConfiguration"), "KubernetesNamespace")
	_pf_batch_lit(ns)
	count(ns) > 63
}
