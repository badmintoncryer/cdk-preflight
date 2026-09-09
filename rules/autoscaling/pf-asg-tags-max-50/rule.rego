package cdk_preflight

import rego.v1

_pf_asgtm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-tags-max-50", "ERROR", name,
	"Properties.Tags",
	sprintf("the group carries %d tags; the limit is 50 and the group create fails with \"You tried to create more tags than allowed\"", [n]),
	"Keep at most 50 tags, counting the ones Tags.of() adds from enclosing scopes", _pf_asgtm_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := count(_pf_aslib_tags(name))
	n > 50
}
