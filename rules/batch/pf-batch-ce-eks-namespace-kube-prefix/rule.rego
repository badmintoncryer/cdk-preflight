package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-namespace-kube-prefix", "ERROR", name,
	"Properties.EksConfiguration.KubernetesNamespace",
	sprintf("KubernetesNamespace %v is reserved (\"kubernetesNamespace cannot be a reserved Kubernetes system namespace\")", [ns]),
	"Use a namespace that does not start with kube-",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	ns := _pf_batch_oget(_pf_batch_get(name, "EksConfiguration"), "KubernetesNamespace")
	_pf_batch_lit(ns)
	startswith(ns, "kube-")
}
