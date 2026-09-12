package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-namespace-format", "ERROR", name,
	"Properties.EksConfiguration.KubernetesNamespace",
	sprintf("KubernetesNamespace %v is not a DNS-1123 label (\"kubernetesNamespace must be a valid Kubernetes namespace.\")", [ns]),
	"Use lowercase letters, digits and hyphens, starting and ending with an alphanumeric",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	ns := _pf_batch_oget(_pf_batch_get(name, "EksConfiguration"), "KubernetesNamespace")
	_pf_batch_lit(ns)
	count(ns) <= 63
	not regex.match(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, ns)
}
