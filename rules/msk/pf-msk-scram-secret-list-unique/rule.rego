package cdk_preflight

import rego.v1

# BatchAssociateScramSecret rejects a repeated ARN outright with "The list provided contains
# duplicate items. ... InvalidParameter: secretArnList" -- the realistic shape is a copy-pasted
# entry in a list that is otherwise correct. The schema does not mark SecretArnList uniqueItems.
_pf_msksu_arns(name) := arns if {
	arns := [a |
		some it in flatten_list(name, "Properties.SecretArnList")
		a := it.value
		is_string(a)
	]
}

violation contains make_diag_full("pf-msk-scram-secret-list-unique", "ERROR", name,
	"Properties.SecretArnList",
	sprintf("SecretArnList has %d entries but only %d distinct ARN(s); the association fails with \"The list provided contains duplicate items\"", [count(arns), count(uniq)]),
	"List each SCRAM secret once",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-password-tutorial.html") if {
	some name in resources_of_type("AWS::MSK::BatchScramSecret")
	arns := _pf_msksu_arns(name)
	count(arns) > 1
	uniq := {a | some a in arns}
	count(uniq) < count(arns)
}
