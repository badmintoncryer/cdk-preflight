package cdk_preflight

import rego.v1

# MRSC is only available inside one of three Region sets, and the deployment
# region itself is part of the set (a replica must exist there). Reading
# data.cdk_preflight.deploy_region makes this a deploy-environment check:
# the same template is legal from us-east-1 and illegal from eu-west-1.
_pf_ddbmrs_all(name) := rs if {
	base := _pf_ddb_replica_regions(name) | _pf_ddb_witness_regions(name)
	rs := base | {r | r := data.cdk_preflight.deploy_region; is_string(r)}
}

_pf_ddbmrs_covered(rs) if {
	some s in _pf_ddb_mrsc_sets
	every r in rs {
		r in s
	}
}

violation contains make_diag_full("pf-dynamodb-global-table-mrsc-region-set", "ERROR", name,
	"Properties.Replicas",
	sprintf("MultiRegionConsistency is STRONG across %s; MRSC global tables cannot span Region sets (US: us-east-1/us-east-2/us-west-2, EU: eu-west-1/eu-west-2/eu-west-3/eu-central-1, AP: ap-northeast-1/ap-northeast-2/ap-northeast-3)", [concat(", ", rs)]),
	"Keep every replica, the witness and the deployment region inside one Region set",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddb_mrsc(name)
	rs := _pf_ddbmrs_all(name)
	count(rs) > 0
	not _pf_ddbmrs_covered(rs)
}
