package cdk_preflight

import rego.v1

_pf_s3nev_fix := "Use an event name from the S3 event type list, e.g. s3:ObjectCreated:Put"

_pf_s3nev_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html"

_pf_s3nev_events := {
	"s3:ObjectCreated:*",
	"s3:ObjectCreated:Put",
	"s3:ObjectCreated:Post",
	"s3:ObjectCreated:Copy",
	"s3:ObjectCreated:CompleteMultipartUpload",
	"s3:ObjectRemoved:*",
	"s3:ObjectRemoved:Delete",
	"s3:ObjectRemoved:DeleteMarkerCreated",
	"s3:ObjectRestore:*",
	"s3:ObjectRestore:Post",
	"s3:ObjectRestore:Completed",
	"s3:ObjectRestore:Delete",
	"s3:ObjectAcl:Put",
	"s3:ObjectTagging:*",
	"s3:ObjectTagging:Put",
	"s3:ObjectTagging:Delete",
	"s3:ReducedRedundancyLostObject",
	"s3:Replication:*",
	"s3:Replication:OperationFailedReplication",
	"s3:Replication:OperationMissedThreshold",
	"s3:Replication:OperationReplicatedAfterThreshold",
	"s3:Replication:OperationNotTracked",
	"s3:LifecycleExpiration:*",
	"s3:LifecycleExpiration:Delete",
	"s3:LifecycleExpiration:DeleteMarkerCreated",
	"s3:LifecycleTransition",
	"s3:IntelligentTiering",
}

violation contains make_diag_full("pf-s3-notification-event-name", "ERROR", name,
	sprintf("Properties.NotificationConfiguration.%v.%d.Event", [c.k, c.i]),
	sprintf("'%v' is not an S3 event type", [ev]),
	_pf_s3nev_fix, _pf_s3nev_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in _pf_s3lib_notifs(name)
	ev := _pf_s3lib_lit(object.get(c.v, "Event", null))
	not _pf_s3nev_events[ev]
}
