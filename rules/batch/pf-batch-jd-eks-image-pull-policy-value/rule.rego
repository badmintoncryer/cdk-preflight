package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-image-pull-policy-value", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the image pull policy %v is not supported (\"Unsupported image pull policy value.\")", [p]),
	"Use Always, IfNotPresent or Never",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainer.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	p := _pf_batch_oget(c.value, "ImagePullPolicy")
	_pf_batch_lit(p)
	not p in {"Always", "IfNotPresent", "Never"}
}
