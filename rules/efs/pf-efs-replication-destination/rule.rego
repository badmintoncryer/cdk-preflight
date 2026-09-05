package cdk_preflight

import rego.v1

_pf_efsrep_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateReplicationConfiguration.html"

_pf_efsrep_fix := "Drop AvailabilityZoneName for a Regional destination, or name an Availability Zone of the destination Region; the destination KMS key must live in the destination Region too"

_pf_efsrep_dests contains [name, i, d] if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	dests := resolve(name, "Properties.ReplicationConfiguration.Destinations")
	is_array(dests)
	some i, d in dests
	is_object(d)
}

violation contains make_diag_full("pf-efs-replication-destination", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Destinations[%d].AvailabilityZoneName", [i]),
	sprintf("the destination Availability Zone '%s' is not in the destination Region '%s'; CreateReplicationConfiguration fails with \"Region and Availability Zone must match.\"", [az, region]),
	_pf_efsrep_fix, _pf_efsrep_url) if {
	some [name, i, d] in _pf_efsrep_dests
	az := object.get(d, "AvailabilityZoneName", null)
	is_string(az)
	region := object.get(d, "Region", null)
	is_string(region)
	not startswith(az, region)
}

violation contains make_diag_full("pf-efs-replication-destination", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Destinations[%d].KmsKeyId", [i]),
	sprintf("the destination key is in region '%s' but the destination file system is created in '%s'; CreateReplicationConfiguration fails with \"Failed to create destination file system: Invalid KMS key ID (unexpected region)\"", [parts[3], region]),
	_pf_efsrep_fix, _pf_efsrep_url) if {
	some [name, i, d] in _pf_efsrep_dests
	region := object.get(d, "Region", null)
	is_string(region)
	parts := _pf_efslib_arn(object.get(d, "KmsKeyId", null))
	parts[2] == "kms"
	parts[3] != region
}
