#!/usr/bin/env python3
"""Generator for the Redshift (provisioned) rule slice of issue #66.

Usage:
  python3 gen-redshift.py            # write every rule in RULES + rules/_lib/redshift.rego
  python3 gen-redshift.py <id>...    # write only the named rules (short id "automated-snapshot-retention-ra3" or full)
  python3 gen-redshift.py --list     # print the candidate-id -> rule-id table

C4b: append your specs to RULES (see the "slice" field) and re-run. Never hand-edit the
generated files; fix the spec here and regenerate. Shared helpers live in LIB below.
"""
import json
import os
import sys

WT = os.environ.get("PF_WORKTREE", "/home/user/wt-redshift")
RULES_DIR = os.path.join(WT, "rules", "redshift")
LIB_PATH = os.path.join(WT, "rules", "_lib", "redshift.rego")
ADDED_ON = "2026-09-22"
API_CREATE = "https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html"
API_MAINT = "https://docs.aws.amazon.com/redshift/latest/APIReference/API_ModifyClusterMaintenance.html"
CFN_CLUSTER = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-cluster.html"
CFN_EVSUB = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-eventsubscription.html"

# ---------------------------------------------------------------------------
# shared lib (rules/_lib/redshift.rego)
# ---------------------------------------------------------------------------
LIB = r'''package cdk_preflight

import rego.v1

# Shared helpers for the Redshift (provisioned) rules. Absence can only be proven on
# input.resources (resolve() is undefined both for a missing key and for an unresolved
# token, see AGENTS.md), so "is the property written" always goes through _pf_redshiftlib_has.
# Node-type comparisons are literal-only (a Ref resolves to a logical id, not a node type).
# Never emits diagnostics (BUNDLED_LIBS).

_pf_redshiftlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_redshiftlib_get(name, k) := v if {
	v := object.get(_pf_redshiftlib_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

_pf_redshiftlib_has(name, k) if {
	_pf_redshiftlib_get(name, k)
}

# True only when the document literally says true (unresolved tokens are not judged).
_pf_redshiftlib_true(name, k) if _pf_redshiftlib_get(name, k) == true

_pf_redshiftlib_true(name, k) if _pf_redshiftlib_get(name, k) == "true"

# Absent, or literally false. An unresolved token is neither, so rules that need
# "not enabled" use this instead of `not _pf_redshiftlib_true` to stay token-safe.
_pf_redshiftlib_false_or_absent(name, k) if not _pf_redshiftlib_has(name, k)

_pf_redshiftlib_false_or_absent(name, k) if _pf_redshiftlib_get(name, k) == false

_pf_redshiftlib_false_or_absent(name, k) if _pf_redshiftlib_get(name, k) == "false"

# A user literal: a string that is not the logical id a Ref/GetAtt resolves to.
_pf_redshiftlib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# Literal string property; undefined for tokens, refs and absent keys.
_pf_redshiftlib_str(name, k) := v if {
	v := resolve(name, sprintf("Properties.%s", [k]))
	_pf_redshiftlib_lit(v)
}

# Numeric property; undefined when absent or unresolvable (to_number(null) would be 0).
_pf_redshiftlib_num(name, k) := n if {
	v := resolve(name, sprintf("Properties.%s", [k]))
	v != null
	n := to_number(v)
}

# Lower-cased literal NodeType ("ra3.large"), and its family ("ra3" / "rg" / "dc2" / "ds2").
_pf_redshiftlib_node_type(name) := lower(v) if {
	v := _pf_redshiftlib_str(name, "NodeType")
}

_pf_redshiftlib_family(name) := f if {
	parts := split(_pf_redshiftlib_node_type(name), ".")
	count(parts) == 2
	f := parts[0]
}

# Families on Redshift Managed Storage: the ones that take the 5431-5455 / 8191-8215 port
# bands, AZ relocation, Multi-AZ, and that cannot disable automated snapshots.
_pf_redshiftlib_rms_families := {"ra3", "rg"}

_pf_redshiftlib_rms(name) if {
	_pf_redshiftlib_family(name) in _pf_redshiftlib_rms_families
}

_pf_redshiftlib_dc2(name) if _pf_redshiftlib_family(name) == "dc2"

# Lower-cased literal ClusterType ("single-node" / "multi-node").
_pf_redshiftlib_cluster_type(name) := lower(v) if {
	v := _pf_redshiftlib_str(name, "ClusterType")
}
'''

# ---------------------------------------------------------------------------
# fixture builders
# ---------------------------------------------------------------------------
BASE_PASSWORD = "Pf66bench1"  # 10 chars, upper + lower + digit, no forbidden char

BASE_CLUSTER = {
    "ClusterType": "single-node",
    "NodeType": "ra3.large",
    "DBName": "dev",
    "MasterUsername": "pfadmin",
    "MasterUserPassword": BASE_PASSWORD,
}


def cluster_template(overrides=None, extra=None):
    """One AWS::Redshift::Cluster (ra3.large single-node, the cheapest creatable shape in
    us-east-1) with property overrides; a None value deletes the key. `extra` adds resources."""
    props = dict(BASE_CLUSTER)
    for k, v in (overrides or {}).items():
        if v is None:
            props.pop(k, None)
        else:
            props[k] = v
    res = {
        "C": {
            "Type": "AWS::Redshift::Cluster",
            "DeletionPolicy": "Delete",
            "UpdateReplacePolicy": "Delete",
            "Properties": props,
        }
    }
    res.update(extra or {})
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": res}


EIP = {"Eip": {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc"}}}


def eventsub_template(rule_id, kind, extra_props):
    props = {
        "SubscriptionName": f"{rule_id}-{kind}",
        "SnsTopicArn": {"Ref": "T"},
    }
    props.update(extra_props)
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "T": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "S": {
                "Type": "AWS::Redshift::EventSubscription",
                "DeletionPolicy": "Delete",
                "UpdateReplacePolicy": "Delete",
                "Properties": props,
            },
        },
    }


def probe(msg, call="CreateCluster", note=""):
    """TARGET-class evidence: phase B api-probe verbatim, bench pending."""
    tail = f" {note}" if note else ""
    return f'api-probe 2026-09-15 us-east-1: {call} -> "{msg}" (#66 phase B){tail}; bench: PENDING'


def bench_only(why):
    return f"api-probe: none (#66 phase B BENCH, {why}); bench: PENDING 2026-09-22 us-east-1"


CLUSTER = "AWS::Redshift::Cluster"
ITER = f'\tsome name in resources_of_type("{CLUSTER}")\n'

# ---------------------------------------------------------------------------
# rule specs. `rego` is the whole module minus the header. Fixtures are either
# cluster overrides (dict / None) or a full template (dict with "Resources").
# ---------------------------------------------------------------------------
RULES = [
    {
        "candidate": "pf-rs-automated-snapshot-retention-ra3",
        "id": "pf-redshift-automated-snapshot-retention-ra3",
        "slice": "a-m",
        "title": "AutomatedSnapshotRetentionPeriod cannot be 0 on RA3/RG node types",
        "source": API_CREATE,
        "evidence": bench_only("ra3 billing_risk high, create-* not called; fail is rejected at CreateCluster, pass creates one ra3.large single-node cluster"),
        "rego": f'''violation contains make_diag_full("pf-redshift-automated-snapshot-retention-ra3", "ERROR", name,
	"Properties.AutomatedSnapshotRetentionPeriod",
	sprintf("AutomatedSnapshotRetentionPeriod %v disables automated snapshots on node type %s; CreateCluster rejects it (\\"You can't disable automated snapshots for RG or RA3 node types. Set the automated retention period from 1-35 days.\\")", [n, nt]),
	"Set AutomatedSnapshotRetentionPeriod to a value from 1 to 35, or omit it (default 1)",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_rms(name)
	nt := _pf_redshiftlib_node_type(name)
	n := _pf_redshiftlib_num(name, "AutomatedSnapshotRetentionPeriod")
	n < 1
}}
''',
        "fail": {"AutomatedSnapshotRetentionPeriod": 0},
        "pass": {"AutomatedSnapshotRetentionPeriod": 1},
    },
    {
        "candidate": "pf-rs-automated-snapshot-retention-range",
        "id": "pf-redshift-automated-snapshot-retention-range",
        "slice": "a-m",
        "title": "AutomatedSnapshotRetentionPeriod must be at most 35 days",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: Invalid automated snapshot retention period: 36. Retention period must be between 0 and 35."),
        "rego": f'''violation contains make_diag_full("pf-redshift-automated-snapshot-retention-range", "ERROR", name,
	"Properties.AutomatedSnapshotRetentionPeriod",
	sprintf("AutomatedSnapshotRetentionPeriod %v exceeds 35; CreateCluster rejects it (\\"Invalid automated snapshot retention period: %v. Retention period must be between 0 and 35.\\")", [n, n]),
	"Use an automated snapshot retention period of 35 days or less",
	"{API_CREATE}") if {{
{ITER}	n := _pf_redshiftlib_num(name, "AutomatedSnapshotRetentionPeriod")
	n > 35
}}
''',
        "fail": {"AutomatedSnapshotRetentionPeriod": 36},
        "pass": {"AutomatedSnapshotRetentionPeriod": 35},
    },
    {
        "candidate": "pf-rs-availability-zone-region",
        "id": "pf-redshift-availability-zone-region",
        "slice": "a-m",
        "title": "AvailabilityZone must belong to the deployment region",
        "source": API_CREATE,
        "evidence": 'api-probe 2026-09-15 us-east-1: CreateCluster with AvailabilityZone us-west-2a -> "InvalidVPCNetworkStateFault: Cluster subnet group default doesn\'t cover the AZ specified." (#66 phase B, UNNAMED: the message names the subnet group, not the region); bench: PENDING. Evaluates only in enforce mode with a concrete app region (deploy_region injection); silent otherwise. Test fixtures assume the harness region us-east-1.',
        "rego": f'''# data.cdk_preflight.deploy_region exists only when the enforce plugin knows the app's
# concrete region (src/private/enforce.ts); otherwise the reference is undefined and the
# rule skips. Only standard AZ names (<region><letter>) are judged; AZ ids and tokens skip.
violation contains make_diag_full("pf-redshift-availability-zone-region", "ERROR", name,
	"Properties.AvailabilityZone",
	sprintf("AvailabilityZone '%s' is not in the deployment region '%s'; CreateCluster rejects it (\\"Cluster subnet group default doesn't cover the AZ specified.\\")", [az, region]),
	"Use an Availability Zone of the region the stack deploys to, or omit AvailabilityZone",
	"{API_CREATE}") if {{
{ITER}	region := data.cdk_preflight.deploy_region
	is_string(region)
	az := _pf_redshiftlib_str(name, "AvailabilityZone")
	regex.match(`^[a-z]{{2}}(-[a-z]+)+-[0-9]+[a-z]$`, az)
	az_region := substring(az, 0, count(az) - 1)
	az_region != region
}}
''',
        "fail": {"AvailabilityZone": "us-west-2a"},
        "pass": {"AvailabilityZone": "us-east-1a"},
    },
    {
        "candidate": "pf-rs-cluster-version-1-0",
        "id": "pf-redshift-cluster-version-1-0",
        "slice": "a-m",
        "title": "ClusterVersion accepts only 1.0",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterCombination: Cannot find Cluster version 2.0"),
        "rego": f'''violation contains make_diag_full("pf-redshift-cluster-version-1-0", "ERROR", name,
	"Properties.ClusterVersion",
	sprintf("ClusterVersion '%s' does not exist; only 1.0 is available and CreateCluster rejects it (\\"Cannot find Cluster version %s\\")", [cv, cv]),
	"Set ClusterVersion to \\"1.0\\" or omit it",
	"{API_CREATE}") if {{
{ITER}	cv := _pf_redshiftlib_str(name, "ClusterVersion")
	cv != "1.0"
}}
''',
        "fail": {"ClusterVersion": "2.0"},
        "pass": {"ClusterVersion": "1.0"},
    },
    {
        "candidate": "pf-rs-dbname-lowercase",
        "id": "pf-redshift-dbname-lowercase",
        "slice": "a-m",
        "title": "DBName must be lowercase, start with a letter and use only [a-z0-9_+.@-]",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: DbName parameter must be lowercase, begin with a letter, contain only alphanumeric characters, underscore ('_'), plus sign ('+'), dot ('.'), at ('@'), or hyphen ('-'), and be less than 64 characters.", note="(the API accepts _ + . @ - as well, so the rule judges the service's own character set, not the doc's \"alphanumeric only\"; length is not judged)"),
        "rego": f'''# The service message (phase B) is the source of truth: lowercase, letter first, and
# the characters a-z 0-9 _ + . @ -. The API doc's "alphanumeric only" is narrower than
# what CreateCluster accepts. Length is left to the engine schema.
violation contains make_diag_full("pf-redshift-dbname-lowercase", "ERROR", name,
	"Properties.DBName",
	sprintf("DBName '%s' is not a lowercase identifier starting with a letter; CreateCluster rejects it (\\"DbName parameter must be lowercase, begin with a letter, contain only alphanumeric characters, underscore ('_'), plus sign ('+'), dot ('.'), at ('@'), or hyphen ('-')\\")", [dn]),
	"Use a lowercase name that starts with a letter and contains only a-z, 0-9, _, +, ., @ and -",
	"{API_CREATE}") if {{
{ITER}	dn := _pf_redshiftlib_str(name, "DBName")
	not regex.match(`^[a-z][a-z0-9_+.@-]*$`, dn)
}}
''',
        "fail": {"DBName": "Pf66db"},
        "pass": {"DBName": "pf66db"},
    },
    {
        "candidate": "pf-rs-defer-maintenance-duration-endtime",
        "id": "pf-redshift-defer-maintenance-duration-endtime",
        "slice": "a-m",
        "title": "DeferMaintenanceDuration and DeferMaintenanceEndTime are mutually exclusive",
        "source": API_MAINT,
        "evidence": bench_only("post-create: ModifyClusterMaintenance runs after CreateCluster, so the fail stack creates one ra3.large single-node cluster before rolling back; API doc: If you specify a duration, you can't specify an end time"),
        "rego": f'''# Judged only when DeferMaintenance is literally true: that is the branch where the
# CloudFormation handler is known to call ModifyClusterMaintenance after CreateCluster.
violation contains make_diag_full("pf-redshift-defer-maintenance-duration-endtime", "ERROR", name,
	"Properties.DeferMaintenanceDuration",
	"DeferMaintenanceDuration is set together with DeferMaintenanceEndTime; ModifyClusterMaintenance rejects the pair after the cluster is created (\\"If you specify a duration, you can't specify an end time.\\")",
	"Keep either DeferMaintenanceDuration or DeferMaintenanceEndTime, not both",
	"{API_MAINT}") if {{
{ITER}	_pf_redshiftlib_true(name, "DeferMaintenance")
	_pf_redshiftlib_has(name, "DeferMaintenanceDuration")
	_pf_redshiftlib_has(name, "DeferMaintenanceEndTime")
}}
''',
        "fail": {"DeferMaintenance": True, "DeferMaintenanceDuration": 30, "DeferMaintenanceEndTime": "2031-01-31T00:00:00Z"},
        "pass": {"DeferMaintenance": True, "DeferMaintenanceDuration": 30},
    },
    {
        "candidate": "pf-rs-defer-maintenance-duration-max",
        "id": "pf-redshift-defer-maintenance-duration-max",
        "slice": "a-m",
        "title": "DeferMaintenanceDuration must be at most 60 days",
        "source": API_MAINT,
        "evidence": bench_only("post-create: ModifyClusterMaintenance runs after CreateCluster, so the fail stack creates one ra3.large single-node cluster before rolling back; API doc (botocore 1.43.62): The duration must be 60 days or less"),
        "rego": f'''# Judged only when DeferMaintenance is literally true (the branch where the handler
# calls ModifyClusterMaintenance after CreateCluster).
violation contains make_diag_full("pf-redshift-defer-maintenance-duration-max", "ERROR", name,
	"Properties.DeferMaintenanceDuration",
	sprintf("DeferMaintenanceDuration %v exceeds 60 days; ModifyClusterMaintenance rejects it after the cluster is created (\\"The duration must be 60 days or less.\\")", [n]),
	"Defer maintenance for 60 days or less, or set DeferMaintenanceEndTime instead",
	"{API_MAINT}") if {{
{ITER}	_pf_redshiftlib_true(name, "DeferMaintenance")
	n := _pf_redshiftlib_num(name, "DeferMaintenanceDuration")
	n > 60
}}
''',
        "fail": {"DeferMaintenance": True, "DeferMaintenanceDuration": 61},
        "pass": {"DeferMaintenance": True, "DeferMaintenanceDuration": 60},
    },
    {
        "candidate": "pf-rs-elastic-ip-publicly-accessible",
        "id": "pf-redshift-elastic-ip-publicly-accessible",
        "slice": "a-m",
        "title": "ElasticIp requires PubliclyAccessible true",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: Elastic IP address can only be specified for clusters in a publicly-accessible VPC.", note="(the check precedes the EIP existence check, so the fail fixture uses the TEST-NET address 203.0.113.10; the pass allocates an AWS::EC2::EIP)"),
        "rego": f'''# PubliclyAccessible defaults to false, so absent counts as not public; an unresolved
# token is not judged.
violation contains make_diag_full("pf-redshift-elastic-ip-publicly-accessible", "ERROR", name,
	"Properties.ElasticIp",
	"ElasticIp is set but PubliclyAccessible is not true; CreateCluster rejects it (\\"Elastic IP address can only be specified for clusters in a publicly-accessible VPC.\\")",
	"Set PubliclyAccessible: true, or drop ElasticIp",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_has(name, "ElasticIp")
	_pf_redshiftlib_false_or_absent(name, "PubliclyAccessible")
}}
''',
        "fail": {"ElasticIp": "203.0.113.10", "PubliclyAccessible": False},
        "pass": cluster_template({"ElasticIp": {"Ref": "Eip"}, "PubliclyAccessible": True}, EIP),
    },
    {
        "candidate": "pf-rs-elastic-ip-vs-az-relocation",
        "id": "pf-redshift-elastic-ip-vs-az-relocation",
        "slice": "a-m",
        "title": "ElasticIp cannot be combined with AvailabilityZoneRelocation",
        "source": API_CREATE,
        "evidence": 'api-probe 2026-09-15 us-east-1: CreateCluster with ElasticIp 203.0.113.10 + AvailabilityZoneRelocation -> "InvalidElasticIpFault: The Elastic IP address 203.0.113.10 does not exist." (#66 phase B HOLD: the EIP existence check comes first, so both fixtures now allocate a real AWS::EC2::EIP in the stack); API doc: Don\'t specify the Elastic IP address for a publicly accessible cluster with availability zone relocation turned on; bench: PENDING',
        "rego": f'''violation contains make_diag_full("pf-redshift-elastic-ip-vs-az-relocation", "ERROR", name,
	"Properties.ElasticIp",
	"ElasticIp is set on a cluster with AvailabilityZoneRelocation enabled; CreateCluster rejects the pair (\\"Don't specify the Elastic IP address for a publicly accessible cluster with availability zone relocation turned on.\\")",
	"Drop ElasticIp, or set AvailabilityZoneRelocation: false",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_has(name, "ElasticIp")
	_pf_redshiftlib_true(name, "AvailabilityZoneRelocation")
}}
''',
        "fail": cluster_template({"ElasticIp": {"Ref": "Eip"}, "PubliclyAccessible": True, "AvailabilityZoneRelocation": True}, EIP),
        "pass": cluster_template({"ElasticIp": {"Ref": "Eip"}, "PubliclyAccessible": True}, EIP),
    },
    {
        "candidate": "pf-rs-eventsub-sourceids-need-sourcetype",
        "id": "pf-redshift-eventsub-sourceids-need-sourcetype",
        "slice": "a-m",
        "types": ["AWS::Redshift::EventSubscription"],
        "title": "EventSubscription SourceIds requires SourceType",
        "source": CFN_EVSUB,
        "evidence": probe("InvalidParameterCombination: If SourceType is null, SourceId must also be null.", call="CreateEventSubscription"),
        "rego": f'''violation contains make_diag_full("pf-redshift-eventsub-sourceids-need-sourcetype", "ERROR", name,
	"Properties.SourceIds",
	"SourceIds is set without SourceType; CreateEventSubscription rejects it (\\"If SourceType is null, SourceId must also be null.\\")",
	"Set SourceType (cluster, cluster-parameter-group, cluster-security-group, cluster-snapshot or scheduled-action), or drop SourceIds",
	"{CFN_EVSUB}") if {{
	some name in resources_of_type("AWS::Redshift::EventSubscription")
	ids := _pf_redshiftlib_get(name, "SourceIds")
	is_array(ids)
	count(ids) > 0
	not _pf_redshiftlib_has(name, "SourceType")
}}
''',
        "fail": eventsub_template("pf-redshift-eventsub-sourceids-need-sourcetype", "fail", {"SourceIds": ["pf66-nosuch-cluster"]}),
        "pass": eventsub_template("pf-redshift-eventsub-sourceids-need-sourcetype", "pass", {}),
    },
    {
        "candidate": "pf-rs-hsm-identifier-pair",
        "id": "pf-redshift-hsm-identifier-pair",
        "slice": "a-m",
        "title": "HsmClientCertificateIdentifier and HsmConfigurationIdentifier must be set together",
        "source": CFN_CLUSTER,
        "evidence": probe("InvalidParameterValue: Either both HsmClientCertificateIdentifier and HsmConfigurationIdentifier should be provided for a cluster using an HSM, or neither should be provided for a cluster not using an HSM."),
        "rego": f'''_pf_rshsm_msg := "only one of HsmClientCertificateIdentifier / HsmConfigurationIdentifier is set; CreateCluster rejects it (\\"Either both HsmClientCertificateIdentifier and HsmConfigurationIdentifier should be provided for a cluster using an HSM, or neither should be provided for a cluster not using an HSM.\\")"

_pf_rshsm_fix := "Set both HSM identifiers, or neither"

violation contains make_diag_full("pf-redshift-hsm-identifier-pair", "ERROR", name,
	"Properties.HsmClientCertificateIdentifier", _pf_rshsm_msg, _pf_rshsm_fix, "{CFN_CLUSTER}") if {{
{ITER}	_pf_redshiftlib_has(name, "HsmClientCertificateIdentifier")
	not _pf_redshiftlib_has(name, "HsmConfigurationIdentifier")
}}

violation contains make_diag_full("pf-redshift-hsm-identifier-pair", "ERROR", name,
	"Properties.HsmConfigurationIdentifier", _pf_rshsm_msg, _pf_rshsm_fix, "{CFN_CLUSTER}") if {{
{ITER}	_pf_redshiftlib_has(name, "HsmConfigurationIdentifier")
	not _pf_redshiftlib_has(name, "HsmClientCertificateIdentifier")
}}
''',
        "fail": {"HsmClientCertificateIdentifier": "pf66-hsm-cert"},
        "pass": {},
    },
    {
        "candidate": "pf-rs-manage-master-password-exclusive",
        "id": "pf-redshift-manage-master-password-exclusive",
        "slice": "a-m",
        "title": "ManageMasterPassword and MasterUserPassword are mutually exclusive",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: Your Amazon Redshift cluster is opting in to manage your password using AWS Secrets Manager. To provide your own password, opt out of managing your password with Secrets Manager."),
        "rego": f'''violation contains make_diag_full("pf-redshift-manage-master-password-exclusive", "ERROR", name,
	"Properties.ManageMasterPassword",
	"ManageMasterPassword is true and MasterUserPassword is also set; CreateCluster rejects the pair (\\"Your Amazon Redshift cluster is opting in to manage your password using AWS Secrets Manager. To provide your own password, opt out of managing your password with Secrets Manager.\\")",
	"Keep only one: ManageMasterPassword: true (Secrets Manager) or MasterUserPassword",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_true(name, "ManageMasterPassword")
	_pf_redshiftlib_has(name, "MasterUserPassword")
}}
''',
        "fail": {"ManageMasterPassword": True},
        "pass": {"ManageMasterPassword": True, "MasterUserPassword": None},
    },
    {
        "candidate": "pf-rs-manual-snapshot-retention-range",
        "id": "pf-redshift-manual-snapshot-retention-range",
        "slice": "a-m",
        "title": "ManualSnapshotRetentionPeriod must be at most 3653 days",
        "source": API_CREATE,
        "evidence": probe("InvalidRetentionPeriodFault: Retention period cannot exceed 3653 days.", note="(only the upper end is probed; -1 means indefinite and is not judged)"),
        "rego": f'''# Only the probed upper end is judged; -1 (indefinite) and the doc's lower end are left alone.
violation contains make_diag_full("pf-redshift-manual-snapshot-retention-range", "ERROR", name,
	"Properties.ManualSnapshotRetentionPeriod",
	sprintf("ManualSnapshotRetentionPeriod %v exceeds 3653 days; CreateCluster rejects it (\\"Retention period cannot exceed 3653 days.\\")", [n]),
	"Use a manual snapshot retention period of 3653 days or less, or -1 to retain indefinitely",
	"{API_CREATE}") if {{
{ITER}	n := _pf_redshiftlib_num(name, "ManualSnapshotRetentionPeriod")
	n > 3653
}}
''',
        "fail": {"ManualSnapshotRetentionPeriod": 3654},
        "pass": {"ManualSnapshotRetentionPeriod": 3653},
    },
    {
        "candidate": "pf-rs-master-password-charset",
        "id": "pf-redshift-master-password-charset",
        "slice": "a-m",
        "title": "MasterUserPassword must be printable ASCII without / @ \" ' \\ or space",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: The parameter MasterUserPassword is not a valid password. Only printable ASCII characters except for '/', '@', '\"', ' ', '\\', ''' may be used."),
        "rego": f'''# Anything outside printable ASCII 0x21-0x7E (which already excludes the space) or one
# of the six characters the service names. Dynamic references and tokens are not judged.
violation contains make_diag_full("pf-redshift-master-password-charset", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword contains a character Redshift forbids; CreateCluster rejects it (\\"Only printable ASCII characters except for '/', '@', '\\"', ' ', '\\\\', \'\'\' may be used.\\")",
	"Remove /, @, double quotes, single quotes, backslashes, spaces and non-ASCII characters, or use ManageMasterPassword",
	"{API_CREATE}") if {{
{ITER}	pw := _pf_redshiftlib_str(name, "MasterUserPassword")
	regex.match(`[^!-~]|[/@"'\\\\]`, pw)
}}
''',
        "fail": {"MasterUserPassword": "Pf66bench@1"},
        "pass": {},
    },
    {
        "candidate": "pf-rs-master-password-composition",
        "id": "pf-redshift-master-password-composition",
        "slice": "a-m",
        "title": "MasterUserPassword needs an uppercase letter, a lowercase letter and a digit",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: The parameter MasterUserPassword must contain at least 1 upper case letter.", note="(the fixture exercises the uppercase branch; the lowercase and digit branches follow the same API constraint list and are unprobed)"),
        "rego": f'''_pf_rspwc_url := "{API_CREATE}"

_pf_rspwc_fix := "Include at least one uppercase letter, one lowercase letter and one digit, or use ManageMasterPassword"

_pf_rspwc_pw(name) := pw if {{
	pw := _pf_redshiftlib_str(name, "MasterUserPassword")
}}

violation contains make_diag_full("pf-redshift-master-password-composition", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword has no uppercase letter; CreateCluster rejects it (\\"The parameter MasterUserPassword must contain at least 1 upper case letter.\\")",
	_pf_rspwc_fix, _pf_rspwc_url) if {{
{ITER}	pw := _pf_rspwc_pw(name)
	not regex.match(`[A-Z]`, pw)
}}

violation contains make_diag_full("pf-redshift-master-password-composition", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword has no lowercase letter; CreateCluster rejects it (the API requires at least one lowercase letter)",
	_pf_rspwc_fix, _pf_rspwc_url) if {{
{ITER}	pw := _pf_rspwc_pw(name)
	not regex.match(`[a-z]`, pw)
}}

violation contains make_diag_full("pf-redshift-master-password-composition", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword has no digit; CreateCluster rejects it (the API requires at least one number)",
	_pf_rspwc_fix, _pf_rspwc_url) if {{
{ITER}	pw := _pf_rspwc_pw(name)
	not regex.match(`[0-9]`, pw)
}}
''',
        "fail": {"MasterUserPassword": "pf66bench1"},
        "pass": {},
    },
    {
        "candidate": "pf-rs-master-password-length",
        "id": "pf-redshift-master-password-length",
        "slice": "a-m",
        "title": "MasterUserPassword must be at least 8 characters",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: Invalid master password. Password should be atleast 8 characters long.", note="(the 64-character upper end is the engine schema's, F3033)"),
        "rego": f'''# The upper end (64) is held by the engine schema (F3033); only the lower end is judged here.
violation contains make_diag_full("pf-redshift-master-password-length", "ERROR", name,
	"Properties.MasterUserPassword",
	sprintf("MasterUserPassword is %v characters, shorter than 8; CreateCluster rejects it (\\"Invalid master password. Password should be atleast 8 characters long.\\")", [count(pw)]),
	"Use a password of 8 to 64 characters, or use ManageMasterPassword",
	"{API_CREATE}") if {{
{ITER}	pw := _pf_redshiftlib_str(name, "MasterUserPassword")
	is_string(pw)
	count(pw) < 8
}}
''',
        "fail": {"MasterUserPassword": "Pf66be1"},
        "pass": {"MasterUserPassword": "Pf66ben1"},
    },
    {
        "candidate": "pf-rs-master-password-secret-kms-requires-manage",
        "id": "pf-redshift-master-password-secret-kms-requires-manage",
        "slice": "a-m",
        "title": "MasterPasswordSecretKmsKeyId requires ManageMasterPassword true",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: You can't set the secret encryption KMS key for this cluster without opting in to manage your admin credentials using AWS Secrets Manager. Opt in to managing your admin credentials with Secrets Manager, then try again."),
        "rego": f'''violation contains make_diag_full("pf-redshift-master-password-secret-kms-requires-manage", "ERROR", name,
	"Properties.MasterPasswordSecretKmsKeyId",
	"MasterPasswordSecretKmsKeyId is set but ManageMasterPassword is not true; CreateCluster rejects it (\\"You can't set the secret encryption KMS key for this cluster without opting in to manage your admin credentials using AWS Secrets Manager.\\")",
	"Set ManageMasterPassword: true (and drop MasterUserPassword), or remove MasterPasswordSecretKmsKeyId",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_has(name, "MasterPasswordSecretKmsKeyId")
	_pf_redshiftlib_false_or_absent(name, "ManageMasterPassword")
}}
''',
        "fail": {"MasterPasswordSecretKmsKeyId": "alias/aws/secretsmanager"},
        "pass": {"ManageMasterPassword": True, "MasterPasswordSecretKmsKeyId": "alias/aws/secretsmanager", "MasterUserPassword": None},
    },
    {
        "candidate": "pf-rs-master-username-reserved-public",
        "id": "pf-redshift-master-username-reserved-public",
        "slice": "a-m",
        "title": "MasterUsername must not be PUBLIC",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: The master username can't be named PUBLIC", note="(only PUBLIC is named by the API; the letter-first rule is unprobed and not judged)"),
        "rego": f'''# Only the literal the API names. Redshift identifiers are case-insensitive, so the
# comparison folds case; the other MasterUsername constraints are not judged.
violation contains make_diag_full("pf-redshift-master-username-reserved-public", "ERROR", name,
	"Properties.MasterUsername",
	sprintf("MasterUsername '%s' is reserved; CreateCluster rejects it (\\"The master username can't be named PUBLIC\\")", [u]),
	"Pick another admin user name",
	"{API_CREATE}") if {{
{ITER}	u := _pf_redshiftlib_str(name, "MasterUsername")
	lower(u) == "public"
}}
''',
        "fail": {"MasterUsername": "PUBLIC"},
        "pass": {},
    },
    {
        "candidate": "pf-rs-multi-node-min-nodes",
        "id": "pf-redshift-multi-node-min-nodes",
        "slice": "a-m",
        "title": "multi-node clusters need NumberOfNodes of at least 2",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: Number of nodes for cluster type multi-node must be greater than or equal to 2.", note="(pass creates a 2-node ra3.large cluster, about $1.09/h while it exists)"),
        "rego": f'''violation contains make_diag_full("pf-redshift-multi-node-min-nodes", "ERROR", name,
	"Properties.NumberOfNodes",
	sprintf("ClusterType multi-node with NumberOfNodes %v; CreateCluster rejects it (\\"Number of nodes for cluster type multi-node must be greater than or equal to 2.\\")", [n]),
	"Use NumberOfNodes 2 or more, or ClusterType single-node",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_cluster_type(name) == "multi-node"
	n := _pf_redshiftlib_num(name, "NumberOfNodes")
	n < 2
}}
''',
        "fail": {"ClusterType": "multi-node", "NumberOfNodes": 1},
        "pass": {"ClusterType": "multi-node", "NumberOfNodes": 2},
    },
]

# ---------------------------------------------------------------------------
# C4b (slice n-z) additions: constants, fixture builders, specs
# ---------------------------------------------------------------------------
CFN_SCHED = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-scheduledaction.html"
MGMT_CLUSTERS = "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html"

SCHED_ROLE = {
    "R": {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "scheduler.redshift.amazonaws.com"}, "Action": "sts:AssumeRole"}],
            },
            "Policies": [{
                "PolicyName": "pf66-redshift-scheduler",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["redshift:PauseCluster", "redshift:ResumeCluster", "redshift:DescribeClusters"], "Resource": "*"}],
                },
            }],
        },
    }
}


def scheduled_action_template(rule_id, kind, extra_props):
    """The base ra3.large cluster (created first, Ref-wired), the scheduler role, and one
    PauseCluster scheduled action. The fail side therefore rolls back only after the
    cluster exists (about 10 minutes); the action itself is never created."""
    props = {
        "ScheduledActionName": f"{rule_id}-{kind}",
        "IamRole": {"Fn::GetAtt": ["R", "Arn"]},
        "TargetAction": {"PauseCluster": {"ClusterIdentifier": {"Ref": "C"}}},
        "Schedule": "cron(0 10 ? * MON *)",
    }
    props.update(extra_props)
    tpl = cluster_template({}, SCHED_ROLE)
    tpl["Resources"]["S"] = {
        "Type": "AWS::Redshift::ScheduledAction",
        "DeletionPolicy": "Delete",
        "UpdateReplacePolicy": "Delete",
        "Properties": props,
    }
    return tpl


def clusters_template(ports):
    """One ra3.large single-node cluster per port (C1, C2, ...), for the band rule whose
    fail / pass must carry every end of both bands."""
    res = {}
    for i, port in enumerate(ports, 1):
        props = dict(BASE_CLUSTER)
        props["Port"] = port
        res[f"C{i}"] = {
            "Type": "AWS::Redshift::Cluster",
            "DeletionPolicy": "Delete",
            "UpdateReplacePolicy": "Delete",
            "Properties": props,
        }
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": res}


SA_SCHED = "pf-redshift-scheduled-action-schedule-format"
SA_ORDER = "pf-redshift-scheduled-action-start-before-end"
RULES += [
    {
        "candidate": "pf-rs-node-type-single-node-support",
        "id": "pf-redshift-node-type-single-node-support",
        "slice": "n-z",
        "title": "ra3.4xlarge, ra3.16xlarge, rg.4xlarge, rg.12xlarge and dc2.8xlarge have no single-node configuration",
        "source": MGMT_CLUSTERS,
        "evidence": bench_only("ra3 billing_risk high, create-* not called; fail is rejected at CreateCluster, pass is 2 x ra3.4xlarge multi-node (about $6.5/h) so run it --fail-only; management guide node table: these types start at 2 nodes"),
        "rego": f'''# Node types whose cluster size starts at 2 in the management guide's node table; the
# literal is lower-cased by the lib, tokens skip.
_pf_rsnts_multi_only := {{"ra3.4xlarge", "ra3.16xlarge", "rg.4xlarge", "rg.12xlarge", "dc2.8xlarge"}}

violation contains make_diag_full("pf-redshift-node-type-single-node-support", "ERROR", name,
	"Properties.ClusterType",
	sprintf("ClusterType single-node on node type %s, which has no single-node configuration (minimum 2 nodes); CreateCluster rejects it", [nt]),
	"Use ClusterType multi-node with NumberOfNodes 2 or more, or a node type that has a single-node configuration (for example ra3.large or ra3.xlplus)",
	"{MGMT_CLUSTERS}") if {{
{ITER}	_pf_redshiftlib_cluster_type(name) == "single-node"
	nt := _pf_redshiftlib_node_type(name)
	nt in _pf_rsnts_multi_only
}}
''',
        "fail": {"NodeType": "ra3.4xlarge"},
        "pass": {"NodeType": "ra3.4xlarge", "ClusterType": "multi-node", "NumberOfNodes": 2},
    },
    {
        "candidate": "pf-rs-port-range-ra3 (+ pf-rs-port-range-ra3-upper)",
        "id": "pf-redshift-port-range-ra3",
        "slice": "n-z",
        "title": "RG and RA3 clusters accept only ports 5431-5455 or 8191-8215",
        "source": CFN_CLUSTER,
        "evidence": bench_only("ra3 billing_risk high, create-* not called; fail puts 5430 / 5456 / 8190 / 8216 on four ra3.large single-node clusters that CreateCluster rejects, pass runs four ra3.large single-node clusters on 5431 / 5455 / 8191 / 8215 (about $2.2/h while they exist); API doc: For clusters with RG or RA3 nodes - Select a port within the ranges 5431-5455 or 8191-8215"),
        "rego": f'''# Only the RMS families (ra3 / rg) are bound to the two bands; dc2 takes 1150-65535 and
# is not judged. Port is judged as a literal number, tokens skip.
_pf_rsport_out(n) if n < 5431

_pf_rsport_out(n) if {{
	n > 5455
	n < 8191
}}

_pf_rsport_out(n) if n > 8215

violation contains make_diag_full("pf-redshift-port-range-ra3", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v on node type %s is outside 5431-5455 and 8191-8215; CreateCluster rejects it for RG and RA3 node types", [n, nt]),
	"Use a port from 5431-5455 or 8191-8215 (the default is 5439), or omit Port",
	"{CFN_CLUSTER}") if {{
{ITER}	_pf_redshiftlib_rms(name)
	nt := _pf_redshiftlib_node_type(name)
	n := _pf_redshiftlib_num(name, "Port")
	_pf_rsport_out(n)
}}
''',
        "fail": clusters_template([5430, 5456, 8190, 8216]),
        "pass": clusters_template([5431, 5455, 8191, 8215]),
    },
    {
        "candidate": "pf-rs-scheduled-action-schedule-format",
        "id": SA_SCHED,
        "slice": "n-z",
        "types": ["AWS::Redshift::ScheduledAction"],
        "title": "ScheduledAction Schedule must be an at(...) or cron(...) expression",
        "source": CFN_SCHED,
        "evidence": probe("InvalidSchedule: Invalid schedule provided. The schedule expression must be encapsulated by cron() or at().", call="CreateScheduledAction", note="(the fixtures create the targeted ra3.large cluster first, so the fail stack rolls back only after the cluster exists, about 10 minutes; the action itself is never created)"),
        "rego": f'''# Only the wrapper is judged (case-folded); the body of at()/cron() is left to the service.
violation contains make_diag_full("{SA_SCHED}", "ERROR", name,
	"Properties.Schedule",
	sprintf("Schedule '%s' is neither at(...) nor cron(...); CreateScheduledAction rejects it (\\"Invalid schedule provided. The schedule expression must be encapsulated by cron() or at().\\")", [s]),
	"Write at(yyyy-mm-ddThh:mm:ss) or cron(Minutes Hours Day-of-month Month Day-of-week Year)",
	"{CFN_SCHED}") if {{
	some name in resources_of_type("AWS::Redshift::ScheduledAction")
	s := _pf_redshiftlib_str(name, "Schedule")
	not regex.match(`^(at|cron)\\(.+\\)$`, lower(s))
}}
''',
        "fail": scheduled_action_template(SA_SCHED, "fail", {"Schedule": "0 10 ? * MON *"}),
        "pass": scheduled_action_template(SA_SCHED, "pass", {}),
    },
    {
        "candidate": "pf-rs-scheduled-action-start-before-end",
        "id": SA_ORDER,
        "slice": "n-z",
        "types": ["AWS::Redshift::ScheduledAction"],
        "title": "ScheduledAction StartTime must be earlier than EndTime",
        "source": CFN_SCHED,
        "evidence": probe("InvalidParameterCombination: The StartTime must be earlier than EndTime.", call="CreateScheduledAction", note="(probed with StartTime after EndTime; the rule also flags StartTime equal to EndTime, which is unprobed. Same cluster-first fixture as the schedule-format rule)"),
        "rego": f'''# ISO 8601 timestamps of the same shape compare correctly as strings (no
# time.parse_rfc3339_ns in this engine); mixed shapes do not match and skip.
_pf_rssase_iso(v) if regex.match(`^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}(\\.[0-9]+)?Z?$`, v)

violation contains make_diag_full("{SA_ORDER}", "ERROR", name,
	"Properties.StartTime",
	sprintf("StartTime %s is not earlier than EndTime %s; CreateScheduledAction rejects it (\\"The StartTime must be earlier than EndTime.\\")", [s, e]),
	"Set StartTime before EndTime, or drop one of them",
	"{CFN_SCHED}") if {{
	some name in resources_of_type("AWS::Redshift::ScheduledAction")
	s := _pf_redshiftlib_str(name, "StartTime")
	e := _pf_redshiftlib_str(name, "EndTime")
	_pf_rssase_iso(s)
	_pf_rssase_iso(e)
	s >= e
}}
''',
        "fail": scheduled_action_template(SA_ORDER, "fail", {"StartTime": "2031-01-09T00:00:00Z", "EndTime": "2031-01-01T00:00:00Z"}),
        "pass": scheduled_action_template(SA_ORDER, "pass", {"StartTime": "2031-01-01T00:00:00Z", "EndTime": "2031-01-09T00:00:00Z"}),
    },
    {
        "candidate": "pf-rs-single-node-node-count",
        "id": "pf-redshift-single-node-node-count",
        "slice": "n-z",
        "title": "single-node clusters must not declare more than one node",
        "source": API_CREATE,
        "evidence": probe("InvalidParameterValue: Number of nodes must be 1 or not be supplied for cluster type single-node."),
        "rego": f'''violation contains make_diag_full("pf-redshift-single-node-node-count", "ERROR", name,
	"Properties.NumberOfNodes",
	sprintf("ClusterType single-node with NumberOfNodes %v; CreateCluster rejects it (\\"Number of nodes must be 1 or not be supplied for cluster type single-node.\\")", [n]),
	"Use NumberOfNodes 1 or omit it, or switch to ClusterType multi-node",
	"{API_CREATE}") if {{
{ITER}	_pf_redshiftlib_cluster_type(name) == "single-node"
	n := _pf_redshiftlib_num(name, "NumberOfNodes")
	n > 1
}}
''',
        "fail": {"NumberOfNodes": 2},
        "pass": {"NumberOfNodes": 1},
    },
]

HEADER = "package cdk_preflight\n\nimport rego.v1\n\n"


def yaml_str(s):
    return json.dumps(s, ensure_ascii=False)


def fixture(spec, kind):
    fx = spec[kind]
    if isinstance(fx, dict) and "Resources" in fx:
        return fx
    return cluster_template(fx)


def write_rule(spec):
    rid = spec["id"]
    d = os.path.join(RULES_DIR, rid)
    os.makedirs(os.path.join(d, "templates"), exist_ok=True)
    types = spec.get("types", [CLUSTER])
    with open(os.path.join(d, "rule.rego"), "w") as f:
        f.write(HEADER + spec["rego"])
    meta = "\n".join([
        f"id: {rid}",
        "service: redshift",
        f"resourceTypes: [{', '.join(types)}]",
        "severity: ERROR",
        f"title: {yaml_str(spec['title'])}",
        f"constraintSource: {spec['source']}",
        "upstream: none",
        "benchRegion: us-east-1",
        "repro:",
        "  method: real-deploy",
        f"  evidence: {yaml_str(spec['evidence'])}",
        f"addedOn: {ADDED_ON}",
        "",
    ])
    with open(os.path.join(d, "meta.yaml"), "w") as f:
        f.write(meta)
    for kind in ("fail", "pass"):
        with open(os.path.join(d, "templates", f"{kind}.template.json"), "w") as f:
            json.dump(fixture(spec, kind), f, indent=2)
            f.write("\n")


def main(argv):
    if "--list" in argv:
        for s in RULES:
            print(f"{s['candidate']} -> {s['id']} [{s['slice']}]")
        return
    want = set(argv)
    os.makedirs(os.path.dirname(LIB_PATH), exist_ok=True)
    with open(LIB_PATH, "w") as f:
        f.write(LIB)
    n = 0
    for s in RULES:
        short = s["id"].replace("pf-redshift-", "")
        if want and s["id"] not in want and short not in want:
            continue
        write_rule(s)
        n += 1
    print(f"wrote {n} rules to {RULES_DIR} and {LIB_PATH}")


if __name__ == "__main__":
    main(sys.argv[1:])
