package cdk_preflight

import rego.v1

# A value that is a user-written literal string (a Ref/GetAtt to a template
# resource resolves to the target logical id, which is not a name or an ARN).
_pf_s3lib_lit(v) := v if {
	is_string(v)
	not input.resources[v]
}

# The region segment of an ARN, or undefined for anything else.
_pf_s3lib_arn_region(v) := r if {
	s := _pf_s3lib_lit(v)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) > 3
	r := parts[3]
	r != ""
}

# The S3 lifecycle "waterfall": a transition may only move down this ladder.
_pf_s3lib_rank := {
	"STANDARD": 0,
	"STANDARD_IA": 1,
	"INTELLIGENT_TIERING": 2,
	"ONEZONE_IA": 3,
	"GLACIER_IR": 4,
	"GLACIER": 5,
	"DEEP_ARCHIVE": 6,
}

# Minimum storage duration billed by a class, for the classes that
# pf-s3-lifecycle-days-order does not already own (STANDARD_IA / ONEZONE_IA).
_pf_s3lib_mindur := {
	"GLACIER_IR": 90,
	"GLACIER": 90,
}

# Every notification configuration of a bucket, tagged with the list it came
# from so a rule can report the exact property path.
_pf_s3lib_notifs(name) := [{"k": k, "i": c.index, "v": c.value} |
	some k in ["QueueConfigurations", "TopicConfigurations", "LambdaConfigurations"]
	some c in flatten_list(name, concat("", ["Properties.NotificationConfiguration.", k]))
	is_object(c.value)
]

# The property that carries the destination ARN in each configuration kind.
_pf_s3lib_notif_dest := {
	"QueueConfigurations": "Queue",
	"TopicConfigurations": "Topic",
	"LambdaConfigurations": "Function",
}
