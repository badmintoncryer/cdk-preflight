package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-annotation-value-length", "ERROR", name,
	"Properties.EksProperties.PodProperties.Metadata.Annotations",
	sprintf("a pod annotation value is %v characters long", [c]),
	"Shorten the annotation value to 255 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksMetadata.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	an := _pf_batch_oget(_pf_batch_meta(name), "Annotations")
	bad := [count(v) | some _, v in an; _pf_batch_lit(v); count(v) > 255]
	count(bad) > 0
	c := bad[0]
}
