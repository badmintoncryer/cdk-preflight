package cdk_preflight

import rego.v1

# Shared helpers for the AWS::DynamoDB::GlobalTable rules. MRSC (multi-Region
# strong consistency) constrains the replica set as a whole, so several rules
# need the same notion of "which Regions does this table touch".
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_ddb_mrsc(name) if resolve(name, "Properties.MultiRegionConsistency") == "STRONG"

_pf_ddb_regions(name, prop) := {r |
	some x in flatten_list(name, sprintf("Properties.%s", [prop]))
	r := object.get(x.value, "Region", null)
	is_string(r)
}

_pf_ddb_replica_regions(name) := _pf_ddb_regions(name, "Replicas")

_pf_ddb_witness_regions(name) := _pf_ddb_regions(name, "GlobalTableWitnesses")

# The three Region sets an MRSC global table can live in (2026-09).
_pf_ddb_mrsc_sets := [
	{"us-east-1", "us-east-2", "us-west-2"},
	{"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1"},
	{"ap-northeast-1", "ap-northeast-2", "ap-northeast-3"},
]
