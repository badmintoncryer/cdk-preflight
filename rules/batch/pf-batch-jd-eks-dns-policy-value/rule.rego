package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-dns-policy-value", "ERROR", name,
	"Properties.EksProperties.PodProperties.DnsPolicy",
	sprintf("the DNS policy %v is not supported (\"Unsupported DNS policy value.\")", [p]),
	"Use Default, ClusterFirst or ClusterFirstWithHostNet",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksPodProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	p := _pf_batch_oget(_pf_batch_pod(name), "DnsPolicy")
	_pf_batch_lit(p)
	not p in {"Default", "ClusterFirst", "ClusterFirstWithHostNet"}
}
