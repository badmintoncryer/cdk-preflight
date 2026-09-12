package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-annotation-key-reserved-prefix", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Annotations",
	sprintf("the pod annotation key %v uses a reserved prefix (\"The prefix ... of the pod annotation key cannot contain terms from the Kubernetes reserved namespaces.\")", [k]),
	"Use your own prefix for pod annotations",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	an := _pf_batch_oget(_pf_batch_meta(name), "Annotations")
	bad := [k | some k, _ in an; _pf_batch_k8s_reserved(k)]
	count(bad) > 0
	k := bad[0]
}
