package cdk_preflight

import rego.v1

# Two rules in one template cannot claim the same name: the second create
# fails because the rule already exists. Only explicit names collide — a rule
# without Name gets a generated one. Measured 2026-09-07 (bench, us-east-1).
violation contains make_diag_full("pf-events-rule-name-duplicate", "ERROR", name,
	"Properties.Name",
	sprintf("Rule name '%s' is used by more than one rule in this template; the second create fails because the rule already exists", [n]),
	"Give each rule its own Name, or leave Name unset and let CloudFormation generate one",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	n := resolve(name, "Properties.Name")
	is_string(n)
	names := [x |
		some other in resources_of_type("AWS::Events::Rule")
		x := resolve(other, "Properties.Name")
		is_string(x)
	]
	count([x | some x in names; x == n]) > 1
}
