package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-elbv2-lambda-target-protocol", "ERROR", name,
	"Properties.Protocol",
	"TargetType lambda cannot take Protocol (\"Protocol cannot be specified for target groups with target type 'lambda'\")",
	"Remove Protocol from the lambda target group",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	resolve(name, "Properties.TargetType") == "lambda"
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "Protocol", "__pf_absent") != "__pf_absent"
}
