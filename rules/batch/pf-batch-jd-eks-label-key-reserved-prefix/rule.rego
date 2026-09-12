package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-label-key-reserved-prefix", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Labels",
	sprintf("the pod label key %v uses a reserved prefix (\"The prefix ... of the pod label key cannot contain terms from the Kubernetes reserved namespaces.\")", [k]),
	"Use your own prefix for pod labels",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	ls := _pf_batch_oget(_pf_batch_meta(name), "Labels")
	bad := [k | some k, _ in ls; _pf_batch_k8s_reserved(k)]
	count(bad) > 0
	k := bad[0]
}
