package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-label-value-format", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Labels",
	sprintf("a pod label value is %v characters long", [c]),
	"Shorten the label value to 63 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	ls := _pf_batch_oget(_pf_batch_meta(name), "Labels")
	bad := [count(v) | some _, v in ls; _pf_batch_lit(v); count(v) > 63]
	count(bad) > 0
	c := bad[0]
}
