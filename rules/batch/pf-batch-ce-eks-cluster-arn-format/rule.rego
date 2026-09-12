package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-cluster-arn-format", "ERROR", name,
	"Properties.EksConfiguration.EksClusterArn",
	sprintf("EksClusterArn is %v (\"eksClusterArn must be an EKS cluster ARN.\"); the cluster name alone is not accepted", [a]),
	"Use the full arn:<partition>:eks:<region>:<account>:cluster/<name> form",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	a := _pf_batch_oget(_pf_batch_get(name, "EksConfiguration"), "EksClusterArn")
	_pf_batch_lit(a)
	not regex.match(`^arn:[a-z0-9-]+:eks:[a-z0-9-]+:[0-9]{12}:cluster/.+$`, a)
}
