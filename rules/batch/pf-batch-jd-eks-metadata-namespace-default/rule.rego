package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-metadata-namespace-default", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Namespace",
	"the pod namespace is default (\"kubernetesNamespace cannot be the default Kubernetes namespace.\")",
	"Run the job in a dedicated namespace",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_oget(_pf_batch_meta(name), "Namespace") == "default"
}
