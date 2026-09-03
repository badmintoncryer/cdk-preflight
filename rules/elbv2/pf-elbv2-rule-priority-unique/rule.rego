package cdk_preflight

import rego.v1

# resolve() turns a Ref/GetAtt to a sibling listener into its logical
# id, so both Ref-wired and identical-literal ListenerArns compare equal.
violation contains make_diag_full("pf-elbv2-rule-priority-unique", "ERROR", r2,
	"Properties.Priority",
	sprintf("Priority %v is also used by '%s' on the same listener (\"Priority '%v' is currently in use\")", [p1, r1, p1]),
	"Give each rule on a listener a distinct priority",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateRule.html") if {
	some r1 in resources_of_type("AWS::ElasticLoadBalancingV2::ListenerRule")
	some r2 in resources_of_type("AWS::ElasticLoadBalancingV2::ListenerRule")
	r1 < r2
	l1 := resolve(r1, "Properties.ListenerArn")
	l2 := resolve(r2, "Properties.ListenerArn")
	l1 == l2
	p1 := to_number(resolve(r1, "Properties.Priority"))
	p2 := to_number(resolve(r2, "Properties.Priority"))
	p1 == p2
}
