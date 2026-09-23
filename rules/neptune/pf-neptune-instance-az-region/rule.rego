package cdk_preflight

import rego.v1

# レンズ 3: AZ 名のリージョン部がデプロイ先と違う。deploy_region は enforce プラグインが
# 焼き込むので、未注入（リージョン未確定）なら判定しない。AZ ID（use1-az1）は対象外。
violation contains make_diag_full("pf-neptune-instance-az-region", "ERROR", name,
	"Properties.AvailabilityZone",
	sprintf("AvailabilityZone %s is in %s but the stack deploys to %s; Neptune rejects the instance at create time", [az, region, data.cdk_preflight.deploy_region]),
	"Pick an Availability Zone of the deployment region",
	"https://docs.aws.amazon.com/neptune/latest/userguide/api-instances.html") if {
	some name in resources_of_type("AWS::Neptune::DBInstance")
	az := resolve(name, "Properties.AvailabilityZone")
	is_string(az)
	regex.match(`^[a-z]{2}(-gov)?-[a-z]+-[0-9][a-z]$`, az)
	region := substring(az, 0, count(az) - 1)
	region != data.cdk_preflight.deploy_region
}
