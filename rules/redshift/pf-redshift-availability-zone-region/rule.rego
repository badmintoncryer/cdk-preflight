package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region exists only when the enforce plugin knows the app's
# concrete region (src/private/enforce.ts); otherwise the reference is undefined and the
# rule skips. Only standard AZ names (<region><letter>) are judged; AZ ids and tokens skip.
violation contains make_diag_full("pf-redshift-availability-zone-region", "ERROR", name,
	"Properties.AvailabilityZone",
	sprintf("AvailabilityZone '%s' is not in the deployment region '%s'; CreateCluster rejects it (\"Cluster subnet group default doesn't cover the AZ specified.\")", [az, region]),
	"Use an Availability Zone of the region the stack deploys to, or omit AvailabilityZone",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	az := _pf_redshiftlib_str(name, "AvailabilityZone")
	regex.match(`^[a-z]{2}(-[a-z]+)+-[0-9]+[a-z]$`, az)
	az_region := substring(az, 0, count(az) - 1)
	az_region != region
}
