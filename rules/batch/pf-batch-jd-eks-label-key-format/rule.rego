package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-label-key-format", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Labels",
	sprintf("the pod label key %v is not a valid name (\"The name %v of the pod label key does not match a valid pattern.\")", [k, k]),
	"Start and end the key name with an alphanumeric character",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	ls := _pf_batch_oget(_pf_batch_meta(name), "Labels")
	bad := [k | some k, _ in ls; not _pf_batch_k8s_name_ok(k)]
	count(bad) > 0
	k := bad[0]
}
