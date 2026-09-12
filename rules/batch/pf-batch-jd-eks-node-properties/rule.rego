package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-node-properties", "ERROR", name,
	"Properties.NodeProperties",
	"the job definition sets both EksProperties and NodeProperties (\"Cannot use both nodeProperties and eksProperties\")",
	"Keep either EksProperties or NodeProperties",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_has(name, "EksProperties")
	_pf_batch_has(name, "NodeProperties")
}
