package cdk_preflight

import rego.v1

# The sizes are string-typed in the schema; the between-relationship is
# a three-way cross-property check. The min>max pair itself is engine
# territory (E3706) and not repeated here.
violation contains make_diag_full("pf-asg-desired-capacity-range", "ERROR", name,
	"Properties.DesiredCapacity",
	sprintf("DesiredCapacity %v is outside [%v, %v]; the group create fails with \"Desired capacity:%v must be between the specified min size:%v and max size:%v\"", [dc, mn, mx, dc, mn, mx]),
	"Keep MinSize <= DesiredCapacity <= MaxSize",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html") if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	dc := to_number(resolve(name, "Properties.DesiredCapacity"))
	mn := to_number(resolve(name, "Properties.MinSize"))
	mx := to_number(resolve(name, "Properties.MaxSize"))
	mn <= mx
	_pf_asgdcr_out(dc, mn, mx)
}

_pf_asgdcr_out(dc, mn, _) if dc < mn

_pf_asgdcr_out(dc, _, mx) if dc > mx
