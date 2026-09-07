package cdk_preflight

import rego.v1

_pf_s3ndr_fix := "Use a queue, topic or function in the region the stack deploys to"

_pf_s3ndr_url := "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html"

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise.
violation contains make_diag_full("pf-s3-notification-destination-region", "ERROR", name,
	sprintf("Properties.NotificationConfiguration.%v.%d.%v", [c.k, c.i, prop]),
	sprintf("the notification destination is in '%v' but the bucket deploys to '%v'; S3 requires the destination in the bucket region", [dr, region]),
	_pf_s3ndr_fix, _pf_s3ndr_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in _pf_s3lib_notifs(name)
	prop := _pf_s3lib_notif_dest[c.k]
	dr := _pf_s3lib_arn_region(object.get(c.v, prop, null))
	region := data.cdk_preflight.deploy_region
	is_string(region)
	dr != region
}
