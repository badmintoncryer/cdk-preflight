package cdk_preflight

import rego.v1

_pf_kmsrep_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-replicakey.html"

_pf_kmsrep_fix := "Create the ReplicaKey in a stack of another region and pass the primary key ARN (arn:<partition>:kms:<other-region>:<account>:key/mrk-...) as a literal or cross-stack value"

# [partition, service, region, account, resource...] of a literal ARN; undefined otherwise
_pf_kmsrep_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

_pf_kmsrep_partition(region) := "aws-cn" if startswith(region, "cn-")

_pf_kmsrep_partition(region) := "aws-us-gov" if startswith(region, "us-gov-")

_pf_kmsrep_partition(region) := "aws" if {
	not startswith(region, "cn-")
	not startswith(region, "us-gov-")
}

violation contains make_diag_full("pf-kms-replica-primary-arn", "ERROR", name,
	"Properties.PrimaryKeyArn",
	sprintf("PrimaryKeyArn refers to key '%s' in this template, so primary and replica would share a region; ReplicateKey fails with \"<region> cannot have a replica because it contains the primary.\"", [p]),
	_pf_kmsrep_fix, _pf_kmsrep_url) if {
	some name in resources_of_type("AWS::KMS::ReplicaKey")
	p := resolve(name, "Properties.PrimaryKeyArn")
	p in resources_of_type("AWS::KMS::Key")
}

violation contains make_diag_full("pf-kms-replica-primary-arn", "ERROR", name,
	"Properties.PrimaryKeyArn",
	sprintf("'%s' is not an ARN; ReplicateKey needs the primary key ARN (arn:<partition>:kms:<region>:<account>:key/mrk-...)", [p]),
	_pf_kmsrep_fix, _pf_kmsrep_url) if {
	some name in resources_of_type("AWS::KMS::ReplicaKey")
	p := resolve(name, "Properties.PrimaryKeyArn")
	is_string(p)
	not startswith(p, "arn:")
	not p in object.keys(input.resources)
}

violation contains make_diag_full("pf-kms-replica-primary-arn", "ERROR", name,
	"Properties.PrimaryKeyArn",
	sprintf("'%s' is not a multi-Region key ARN (the key id must start with mrk-); ReplicateKey fails with \"is not a multi-region key.\"", [p]),
	_pf_kmsrep_fix, _pf_kmsrep_url) if {
	some name in resources_of_type("AWS::KMS::ReplicaKey")
	p := resolve(name, "Properties.PrimaryKeyArn")
	parts := _pf_kmsrep_arn(p)
	parts[2] == "kms"
	not startswith(parts[5], "key/mrk-")
}

# Region / partition comparison needs the deploy region (enforce mode only).
violation contains make_diag_full("pf-kms-replica-primary-arn", "ERROR", name,
	"Properties.PrimaryKeyArn",
	sprintf("primary key is in '%s', the same region this replica deploys to; ReplicateKey fails with \"%s cannot have a replica because it contains the primary.\"", [region, region]),
	_pf_kmsrep_fix, _pf_kmsrep_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::KMS::ReplicaKey")
	parts := _pf_kmsrep_arn(resolve(name, "Properties.PrimaryKeyArn"))
	parts[2] == "kms"
	parts[3] == region
}

violation contains make_diag_full("pf-kms-replica-primary-arn", "ERROR", name,
	"Properties.PrimaryKeyArn",
	sprintf("primary key is in partition '%s' but this stack deploys to '%s' (%s); ReplicateKey fails with \"The replica key Region must be in the same AWS partition as the primary key Region.\"", [parts[1], region, _pf_kmsrep_partition(region)]),
	_pf_kmsrep_fix, _pf_kmsrep_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::KMS::ReplicaKey")
	parts := _pf_kmsrep_arn(resolve(name, "Properties.PrimaryKeyArn"))
	parts[2] == "kms"
	parts[1] != _pf_kmsrep_partition(region)
}
