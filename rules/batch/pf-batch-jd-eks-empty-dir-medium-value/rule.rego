package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-empty-dir-medium-value", "ERROR", name,
	"Properties.EksProperties.PodProperties.Volumes",
	sprintf("the empty directory medium %v is not supported (\"Invalid Volume mount. Allowed values - Memory or null.\")", [m]),
	"Leave Medium unset, or set it to Memory",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksEmptyDir.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in flatten_list(name, "Properties.EksProperties.PodProperties.Volumes")
	m := _pf_batch_oget(_pf_batch_oget(v.value, "EmptyDir"), "Medium")
	_pf_batch_lit(m)
	not m in {"", "Memory"}
}
