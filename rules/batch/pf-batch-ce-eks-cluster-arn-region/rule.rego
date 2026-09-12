package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-cluster-arn-region", "ERROR", name,
	"Properties.EksConfiguration.EksClusterArn",
	sprintf("EksClusterArn points at %v (\"eksClusterArn must be in the same AWS region as the compute environment\")", [r]),
	"Reference a cluster in the deployment region",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	a := _pf_batch_oget(_pf_batch_get(name, "EksConfiguration"), "EksClusterArn")
	r := _pf_batch_region_mismatch(a)
}
