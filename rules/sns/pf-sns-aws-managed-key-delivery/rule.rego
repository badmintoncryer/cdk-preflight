package cdk_preflight

import rego.v1

# CloudWatch alarms and EventBridge publish to a topic as themselves (a service
# principal), and the key policy of the AWS managed key alias/aws/sns cannot be
# changed to let them use it. A topic encrypted with that key therefore accepts the
# alarm action or the rule target at deploy time and then every publish from them
# fails. S3 notifications are left out (they send a test message and fail the deploy).
_pf_snsamk_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html#compatibility-with-aws-services"

_pf_snsamk_fix := "Leave the topic unencrypted, or encrypt it with a customer managed key whose key policy lets the publishing service use it"

_pf_snsamk_topic(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	k := resolve(t, "Properties.KmsMasterKeyId")
	is_string(k)
	_pf_amk_alias(k, "sns")
}

_pf_snsamk_sender contains [name, sprintf("Properties.%s.%d", [key, a.index]), "CloudWatch"] if {
	some type in {"AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm"}
	some name in resources_of_type(type)
	some key in _pf_cwlib_action_keys
	some a in flatten_list(name, sprintf("Properties.%s", [key]))
}

_pf_snsamk_sender contains [name, sprintf("Properties.Targets.%d.Arn", [t.index]), "EventBridge"] if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
}

violation contains make_diag_full("pf-sns-aws-managed-key-delivery", "ERROR", name, path,
	sprintf("topic '%s' is encrypted with the AWS managed key alias/aws/sns, which %s cannot use; every publish from it fails", [t, svc]),
	_pf_snsamk_fix, _pf_snsamk_url) if {
	some [name, path, svc] in _pf_snsamk_sender
	t := resolve(name, path)
	_pf_snsamk_topic(t)
}
