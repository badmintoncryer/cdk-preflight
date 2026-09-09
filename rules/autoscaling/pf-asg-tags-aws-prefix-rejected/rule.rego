package cdk_preflight

import rego.v1

_pf_asgtap_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-tags-aws-prefix-rejected", "ERROR", name,
	sprintf("Properties.Tags.%d.Key", [i]),
	sprintf("tag key '%s' uses the aws: prefix, which AWS reserves for its own tags; the group create fails with \"Your account is not allowed to create tag %s\"", [k, k]),
	"Use a prefix of your own", _pf_asgtap_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, t in _pf_aslib_tags(name)
	is_object(t)
	k := object.get(t, "Key", null)
	_pf_aslib_lit(k)
	startswith(k, "aws:")
}
