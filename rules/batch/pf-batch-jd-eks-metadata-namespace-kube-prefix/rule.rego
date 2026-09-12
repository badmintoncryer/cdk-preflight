package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-metadata-namespace-kube-prefix", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Namespace",
	sprintf("the pod namespace %v is a reserved Kubernetes system namespace (\"kubernetesNamespace cannot be a reserved Kubernetes system namespace.\")", [ns]),
	"Run the job in a namespace that does not start with kube-",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	ns := _pf_batch_oget(_pf_batch_meta(name), "Namespace")
	_pf_batch_lit(ns)
	startswith(ns, "kube-")
}
