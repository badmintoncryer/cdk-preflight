package cdk_preflight

import rego.v1

_pf_ec2fl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-flowlog.html"

_pf_ec2fl_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

_pf_ec2fla_bad(name) := v if {
	v := resolve(name, "Properties.MaxAggregationInterval")
	n := to_number(v)
	not n in {60, 600}
}

violation contains make_diag_full("pf-ec2-flow-log-aggregation-interval", "ERROR", name,
	"Properties.MaxAggregationInterval",
	sprintf("MaxAggregationInterval %v is not accepted; a flow log takes 60 or 600 seconds (\"Invalid Flow Log Max Aggregation Interval.\")", [v]),
	"Set MaxAggregationInterval to 60 (one minute) or 600 (ten minutes), or drop the property to take the 600 default",
	_pf_ec2fl_url) if {
	some name in resources_of_type("AWS::EC2::FlowLog")
	v := _pf_ec2fla_bad(name)
}
