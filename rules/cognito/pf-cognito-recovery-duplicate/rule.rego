package cdk_preflight

import rego.v1

# Pairwise duplicate check on the mechanism list; the service error names
# both duplicate priorities and duplicate mechanism names.
_pf_cogrdp_dup(a, b) if {
	pa := to_number(object.get(a, "Priority", -1))
	pb := to_number(object.get(b, "Priority", -2))
	pa == pb
}

_pf_cogrdp_dup(a, b) if {
	n := object.get(a, "Name", "__pf_a")
	is_string(n)
	n == object.get(b, "Name", "__pf_b")
}

violation contains make_diag_full("pf-cognito-recovery-duplicate", "ERROR", name,
	sprintf("Properties.AccountRecoverySetting.RecoveryMechanisms.%d", [b.index]),
	"Recovery mechanisms repeat a priority or name; the pool create fails with \"Account Recovery Setting cannot have duplicate priorities or recovery mechanisms.\"",
	"Give each recovery mechanism a distinct priority and name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cognito-userpool-recoveryoption.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.AccountRecoverySetting.RecoveryMechanisms")
	some b in flatten_list(name, "Properties.AccountRecoverySetting.RecoveryMechanisms")
	a.index < b.index
	is_object(a.value)
	is_object(b.value)
	_pf_cogrdp_dup(a.value, b.value)
}
