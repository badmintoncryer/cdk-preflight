package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-propagate-tags", "ERROR", name,
	"Properties.PropagateTags",
	"an EKS job definition sets PropagateTags (\"Batch on EKS does not support tag propagation.\")",
	"Drop PropagateTags",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_has(name, "EksProperties")
	_pf_batch_get(name, "PropagateTags") == true
}
