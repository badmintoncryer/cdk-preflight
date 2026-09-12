package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-namespace-default", "ERROR", name,
	"Properties.EksConfiguration.KubernetesNamespace",
	"KubernetesNamespace is \"default\" (\"kubernetesNamespace cannot be the default Kubernetes namespace\")",
	"Give the compute environment its own namespace",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_oget(_pf_batch_get(name, "EksConfiguration"), "KubernetesNamespace") == "default"
}
