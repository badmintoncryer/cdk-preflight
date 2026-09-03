package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-service-lb-target-exclusive", "ERROR", name,
	"Properties.LoadBalancers",
	"A LoadBalancers entry sets both TargetGroupArn and LoadBalancerName; CreateService fails with \"loadBalancerName and targetGroupArn cannot both be specified\"",
	"Keep exactly one of TargetGroupArn (ALB/NLB) or LoadBalancerName (CLB) per entry",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some item in flatten_list(name, "Properties.LoadBalancers")
	entry := item.value
	is_object(entry)
	not object.get(entry, "TargetGroupArn", "__pf_absent") == "__pf_absent"
	not object.get(entry, "LoadBalancerName", "__pf_absent") == "__pf_absent"
}
