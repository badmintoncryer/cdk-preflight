#!/usr/bin/env python3
"""Generator for the DocumentDB slice of #66 (C1): writes rules/docdb/<rule-id>/{rule.rego,meta.yaml,templates/*},
rules/_lib/docdb.rego, the pf-docdb- lines of rules/_boundary-exceptions.txt and pending-docdb.txt.
Fixes go here, then re-run:  python3 gen-docdb.py /home/user/wt-docdb
"""
import json
import os
import re
import shutil
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/home/user/wt-docdb"
SURVEY = os.path.dirname(os.path.abspath(__file__))
ADDED = "2026-09-22"
PROBE = "api-probe 2026-09-15 us-east-1"
CFN_CLUSTER = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html"
CFN_SNG = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html"
CFN_EVSUB = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-eventsubscription.html"
API_CLUSTER = "https://docs.aws.amazon.com/documentdb/latest/developerguide/API_CreateDBCluster.html"
API_INSTANCE = "https://docs.aws.amazon.com/documentdb/latest/developerguide/API_CreateDBInstance.html"
API_SV2 = "https://docs.aws.amazon.com/documentdb/latest/developerguide/API_ServerlessV2ScalingConfiguration.html"
DOC_CLASSES = "https://docs.aws.amazon.com/documentdb/latest/developerguide/db-instance-classes.html"

HEADER = "package cdk_preflight\n\nimport rego.v1\n\n"

# ---------------------------------------------------------------- fixtures

def res(rtype, props, policies=True):
    r = {"Type": rtype}
    if policies:
        r["DeletionPolicy"] = "Delete"
        r["UpdateReplacePolicy"] = "Delete"
    r["Properties"] = props
    return r


def cluster(extra=None, creds=True, lid="C"):
    p = {}
    if creds:
        p["MasterUsername"] = "benchuser"
        p["MasterUserPassword"] = "benchpass123"
    if extra:
        p.update(extra)
    return {lid: res("AWS::DocDB::DBCluster", p)}


def net(azs):
    """VPC + one /24 subnet per entry of azs (literal AZ names so the rule can read them)."""
    out = {"V": res("AWS::EC2::VPC", {"CidrBlock": "10.0.0.0/16"}, policies=False)}
    for i, az in enumerate(azs):
        out["S%d" % i] = res("AWS::EC2::Subnet", {
            "VpcId": {"Ref": "V"},
            "CidrBlock": "10.0.%d.0/24" % i,
            "AvailabilityZone": az,
        }, policies=False)
    return out


def subnet_group(azs, name=None):
    out = net(azs)
    p = {"DBSubnetGroupDescription": "cdkpf", "SubnetIds": [{"Ref": "S%d" % i} for i in range(len(azs))]}
    if name is not None:
        p["DBSubnetGroupName"] = name
    out["G"] = res("AWS::DocDB::DBSubnetGroup", p)
    return out


def eventsub(extra=None):
    p = {"SnsTopicArn": {"Ref": "T"}}
    if extra:
        p.update(extra)
    return {"T": res("AWS::SNS::Topic", {}, policies=False), "E": res("AWS::DocDB::EventSubscription", p)}


def restore(extra):
    out = cluster(lid="Src")
    p = {"SourceDBClusterIdentifier": {"Ref": "Src"}}
    p.update(extra)
    out["R"] = res("AWS::DocDB::DBCluster", p)
    return out


def instance(az):
    out = cluster()
    out["I"] = res("AWS::DocDB::DBInstance", {
        "DBClusterIdentifier": {"Ref": "C"},
        "DBInstanceClass": "db.t3.medium",
        "AvailabilityZone": az,
    })
    return out


def tpl(resources):
    return {"Resources": resources}

# ---------------------------------------------------------------- rules

RULES = []


def rule(rid, cand, types, title, source, evidence, rego, fail, pass_, api="CreateDBCluster"):
    RULES.append(dict(id=rid, cand=cand, types=types, title=title, source=source, evidence=evidence,
                      rego=rego, fail=fail, pass_=pass_, api=api))


def target(api, msg, note=""):
    n = (" " + note) if note else ""
    return '%s: %s -> "%s" (#66 phase B TARGET%s); bench: PENDING' % (PROBE, api, msg.replace('"', '\\"'), n)


def bench(reason):
    return "api-probe: none (#66 phase B BENCH: %s); bench: PENDING %s us-east-1" % (reason, ADDED)


# 1 backup window must not overlap maintenance window (same-day, non-wrapping windows only — under-claim like pf-rds-window-overlap)
rule("pf-docdb-backup-maintenance-overlap", "pf-ddb-backup-maintenance-overlap", ["AWS::DocDB::DBCluster"],
     "The backup window and the maintenance window must not overlap", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: The backup window and maintenance window must not overlap.",
            "backup 07:00-07:30 vs maintenance mon:07:29-mon:07:59 (1 min); control mon:07:30-mon:08:00 accepted"),
     HEADER + r'''# The backup window recurs daily, so a same-day maintenance window overlaps whenever the
# time-of-day intervals intersect. Claim scope: both windows well-formed, neither wrapping
# midnight, maintenance window on a single day (other shapes stay silent, under-claim).
violation contains make_diag_full("pf-docdb-backup-maintenance-overlap", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("Backup window %s overlaps maintenance window %s; DocumentDB rejects the pair (\"The backup window and maintenance window must not overlap.\")", [bw, mw]),
	"Separate the two windows in time",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	bw := _pf_docdb_lit(name, "Properties.PreferredBackupWindow")
	bp := split(bw, "-")
	count(bp) == 2
	bs := _pf_docdb_hm(bp[0])
	be := _pf_docdb_hm(bp[1])
	bs < be
	mw := _pf_docdb_lit(name, "Properties.PreferredMaintenanceWindow")
	mp := split(lower(mw), "-")
	count(mp) == 2
	m1 := split(mp[0], ":")
	m2 := split(mp[1], ":")
	count(m1) == 3
	count(m2) == 3
	m1[0] == m2[0]
	ms := _pf_docdb_hm(sprintf("%s:%s", [m1[1], m1[2]]))
	me := _pf_docdb_hm(sprintf("%s:%s", [m2[1], m2[2]]))
	ms < me
	bs < me
	ms < be
}
''',
     tpl(cluster({"PreferredBackupWindow": "07:00-07:30", "PreferredMaintenanceWindow": "mon:07:29-mon:07:59"})),
     tpl(cluster({"PreferredBackupWindow": "07:00-07:30", "PreferredMaintenanceWindow": "mon:07:30-mon:08:00"})))

# 2 backup window >= 30 minutes
rule("pf-docdb-backup-window-duration", "pf-ddb-backup-window-duration", ["AWS::DocDB::DBCluster"],
     "The backup window must be at least 30 minutes", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: Backup window must be at least 30 minutes.", "29-minute window; 30-minute control accepted"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-backup-window-duration", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is only %v minutes; DocumentDB requires at least 30 (\"Backup window must be at least 30 minutes.\")", [w, d]),
	"Widen the window to 30 minutes or more",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredBackupWindow")
	parts := split(w, "-")
	count(parts) == 2
	s := _pf_docdb_hm(parts[0])
	e := _pf_docdb_hm(parts[1])
	d := ((e - s) + 1440) % 1440
	d < 30
}
''',
     tpl(cluster({"PreferredBackupWindow": "07:00-07:29"})),
     tpl(cluster({"PreferredBackupWindow": "07:00-07:30"})))

# 3 backup window format hh24:mi-hh24:mi
rule("pf-docdb-backup-window-format", "pf-ddb-backup-window-format", ["AWS::DocDB::DBCluster"],
     "PreferredBackupWindow must be hh24:mi-hh24:mi", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: Invalid backup window time '0700' specified. Should be specified as a time hh24:mi (24H Clock UTC). Example: 03:15", "value 0700-0730"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-backup-window-format", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is not hh24:mi-hh24:mi (24H clock UTC); DocumentDB rejects it at create time (\"Should be specified as a time hh24:mi (24H Clock UTC). Example: 03:15\")", [w]),
	"Use the hh24:mi-hh24:mi form, e.g. 07:00-07:30",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredBackupWindow")
	not regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`, w)
}
''',
     tpl(cluster({"PreferredBackupWindow": "0700-0730"})),
     tpl(cluster({"PreferredBackupWindow": "07:00-07:30"})))

# 4 event subscription: SourceIds needs SourceType
rule("pf-docdb-eventsub-sourceids-need-sourcetype", "pf-ddb-eventsub-sourceids-need-sourcetype", ["AWS::DocDB::EventSubscription"],
     "SourceIds requires SourceType", CFN_EVSUB,
     target("CreateEventSubscription", "InvalidParameterCombination: If SourceType is null, SourceId must also be null."),
     HEADER + r'''violation contains make_diag_full("pf-docdb-eventsub-sourceids-need-sourcetype", "ERROR", name,
	"Properties.SourceIds",
	"SourceIds is set without SourceType (\"If SourceType is null, SourceId must also be null.\")",
	"Set SourceType (e.g. db-cluster), or drop SourceIds",
	"''' + CFN_EVSUB + r'''") if {
	some name in resources_of_type("AWS::DocDB::EventSubscription")
	ids := _pf_docdb_get(name, "SourceIds")
	is_array(ids)
	count(ids) > 0
	not _pf_docdb_has(name, "SourceType")
}
''',
     tpl(eventsub({"SourceIds": ["cdkpf-nonexistent"]})),
     tpl(eventsub()),
     api="CreateEventSubscription")

# 5 instance AZ must belong to the deploy region (BENCH: needs a real parent cluster)
rule("pf-docdb-instance-az-region", "pf-ddb-instance-az-region", ["AWS::DocDB::DBInstance"],
     "AvailabilityZone must be an Availability Zone of the deploy region", API_INSTANCE,
     bench("CreateDBInstance needs a real parent cluster, DBClusterNotFound came first"),
     HEADER + r'''# Silent when the app has no concrete region (data.cdk_preflight.deploy_region is only
# injected in enforce mode with a concrete env) and for AZs wired via Fn::Select/Fn::GetAZs.
violation contains make_diag_full("pf-docdb-instance-az-region", "ERROR", name,
	"Properties.AvailabilityZone",
	sprintf("'%s' is not an Availability Zone of '%s', the region this stack deploys to; CreateDBInstance rejects it", [az, region]),
	"Write the zone as the deploy region plus a letter, e.g. Fn::Select over Fn::GetAZs",
	"''' + API_INSTANCE + r'''") if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::DocDB::DBInstance")
	az := _pf_docdb_lit(name, "Properties.AvailabilityZone")
	not startswith(az, region)
}
''',
     tpl(instance("us-west-2a")),
     tpl(instance("us-east-1a")),
     api="CreateDBInstance")

# 6 maintenance window >= 30 minutes
rule("pf-docdb-maintenance-window-duration", "pf-ddb-maintenance-window-duration", ["AWS::DocDB::DBCluster"],
     "The maintenance window must be at least 30 minutes", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: Maintenance window must be at least 30 minutes.", "29-minute window; 30-minute control accepted"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-maintenance-window-duration", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("PreferredMaintenanceWindow '%s' is only %v minutes; DocumentDB requires at least 30 (\"Maintenance window must be at least 30 minutes.\")", [w, d]),
	"Widen the window to 30 minutes or more",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredMaintenanceWindow")
	parts := split(w, "-")
	count(parts) == 2
	s := _pf_docdb_dhm(parts[0])
	e := _pf_docdb_dhm(parts[1])
	d := ((e - s) + 10080) % 10080
	d < 30
}
''',
     tpl(cluster({"PreferredMaintenanceWindow": "mon:07:00-mon:07:29"})),
     tpl(cluster({"PreferredMaintenanceWindow": "mon:07:00-mon:07:30"})))

# 7 maintenance window format ddd:hh24:mi-ddd:hh24:mi
rule("pf-docdb-maintenance-window-format", "pf-ddb-maintenance-window-format", ["AWS::DocDB::DBCluster"],
     "PreferredMaintenanceWindow must be ddd:hh24:mi-ddd:hh24:mi", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: Invalid maintenance window time '07:30' specified. Should be specified as a time ddd:hh24:mi (24H Clock UTC). Example: Mon:00:15", "value 07:30-08:00 (no day)"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-maintenance-window-format", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("PreferredMaintenanceWindow '%s' is not ddd:hh24:mi-ddd:hh24:mi (24H clock UTC); DocumentDB rejects it at create time (\"Should be specified as a time ddd:hh24:mi (24H Clock UTC). Example: Mon:00:15\")", [w]),
	"Use the ddd:hh24:mi-ddd:hh24:mi form, e.g. mon:07:30-mon:08:00",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredMaintenanceWindow")
	not regex.match(`^(mon|tue|wed|thu|fri|sat|sun):([01][0-9]|2[0-3]):[0-5][0-9]-(mon|tue|wed|thu|fri|sat|sun):([01][0-9]|2[0-3]):[0-5][0-9]$`, lower(w))
}
''',
     tpl(cluster({"PreferredMaintenanceWindow": "07:30-08:00"})),
     tpl(cluster({"PreferredMaintenanceWindow": "mon:07:30-mon:08:00"})))

# 8 ManageMasterUserPassword xor MasterUserPassword
rule("pf-docdb-manage-master-password-exclusive", "pf-ddb-manage-master-password-exclusive", ["AWS::DocDB::DBCluster"],
     "ManageMasterUserPassword and MasterUserPassword are mutually exclusive", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: MasterUserPassword and ManageMasterUserPassword are mutually exclusive. Specify only one of these parameters."),
     HEADER + r'''violation contains make_diag_full("pf-docdb-manage-master-password-exclusive", "ERROR", name,
	"Properties.ManageMasterUserPassword",
	"ManageMasterUserPassword is true together with MasterUserPassword (\"MasterUserPassword and ManageMasterUserPassword are mutually exclusive. Specify only one of these parameters.\")",
	"Keep only one of the two",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	_pf_docdb_true(name, "ManageMasterUserPassword")
	_pf_docdb_has(name, "MasterUserPassword")
}
''',
     tpl(cluster({"ManageMasterUserPassword": True})),
     tpl(cluster({"MasterUsername": "benchuser", "ManageMasterUserPassword": True}, creds=False)))

# 9 MasterUserPassword >= 8 characters (upper bound 100 not probed, left out)
rule("pf-docdb-master-password-length", "pf-ddb-master-password-length", ["AWS::DocDB::DBCluster"],
     "MasterUserPassword must be at least 8 characters", API_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters.", "7-character password; 8-character control accepted"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-master-password-length", "ERROR", name,
	"Properties.MasterUserPassword",
	sprintf("MasterUserPassword is %v characters; DocumentDB requires at least 8 (\"The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters.\")", [count(pw)]),
	"Use 8 or more characters, or ManageMasterUserPassword / a Secrets Manager reference",
	"''' + API_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	pw := _pf_docdb_lit(name, "Properties.MasterUserPassword")
	is_string(pw)
	count(pw) < 8
}
''',
     tpl(cluster({"MasterUserPassword": "bench12"})),
     tpl(cluster({"MasterUserPassword": "bench123"})))

# 10 MasterUserSecretKmsKeyId requires ManageMasterUserPassword
rule("pf-docdb-master-user-secret-kms-requires-manage", "pf-ddb-master-user-secret-kms-requires-manage", ["AWS::DocDB::DBCluster"],
     "MasterUserSecretKmsKeyId requires ManageMasterUserPassword", CFN_CLUSTER,
     target("CreateDBCluster", "InvalidParameterValue: A ManageMasterUserPassword value is required when MasterUserSecretKmsKeyId is specified."),
     HEADER + r'''# Claim scope: ManageMasterUserPassword absent. An explicit false was not probed and stays silent.
violation contains make_diag_full("pf-docdb-master-user-secret-kms-requires-manage", "ERROR", name,
	"Properties.MasterUserSecretKmsKeyId",
	"MasterUserSecretKmsKeyId is set without ManageMasterUserPassword (\"A ManageMasterUserPassword value is required when MasterUserSecretKmsKeyId is specified.\")",
	"Set ManageMasterUserPassword: true (and drop MasterUserPassword), or drop MasterUserSecretKmsKeyId",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	_pf_docdb_has(name, "MasterUserSecretKmsKeyId")
	not _pf_docdb_has(name, "ManageMasterUserPassword")
}
''',
     tpl(cluster({"MasterUserSecretKmsKeyId": "alias/aws/secretsmanager"})),
     tpl(cluster({"MasterUsername": "benchuser", "ManageMasterUserPassword": True, "MasterUserSecretKmsKeyId": "alias/aws/secretsmanager"}, creds=False)))

# 11 RestoreToTime cannot be combined with RestoreType copy-on-write (BENCH)
rule("pf-docdb-restore-copy-on-write-time", "pf-ddb-restore-copy-on-write-time", ["AWS::DocDB::DBCluster"],
     "RestoreToTime cannot be specified for a copy-on-write restore", CFN_CLUSTER,
     bench("RestoreDBClusterToPointInTime needs a real source cluster, DBClusterNotFound came first; fixtures carry the source cluster in-template"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-restore-copy-on-write-time", "ERROR", name,
	"Properties.RestoreToTime",
	"RestoreToTime is set on a copy-on-write restore; DocumentDB rejects RestoreToTime when RestoreType is copy-on-write",
	"Drop RestoreToTime (a clone always uses the latest restorable time), or use RestoreType full-copy",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	rt := _pf_docdb_lit(name, "Properties.RestoreType")
	lower(rt) == "copy-on-write"
	_pf_docdb_has(name, "RestoreToTime")
}
''',
     tpl(restore({"RestoreType": "copy-on-write", "RestoreToTime": "2026-09-22T00:00:00Z"})),
     tpl(restore({"RestoreType": "copy-on-write", "UseLatestRestorableTime": True})),
     api="RestoreDBClusterToPointInTime")

# 12 RestoreToTime cannot be combined with UseLatestRestorableTime (BENCH)
rule("pf-docdb-restore-time-exclusive", "pf-ddb-restore-time-exclusive", ["AWS::DocDB::DBCluster"],
     "RestoreToTime and UseLatestRestorableTime are mutually exclusive", CFN_CLUSTER,
     bench("RestoreDBClusterToPointInTime needs a real source cluster, DBClusterNotFound came first; fixtures carry the source cluster in-template"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-restore-time-exclusive", "ERROR", name,
	"Properties.RestoreToTime",
	"RestoreToTime is set together with UseLatestRestorableTime: true; DocumentDB rejects the pair",
	"Keep only one of RestoreToTime and UseLatestRestorableTime",
	"''' + CFN_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	_pf_docdb_has(name, "RestoreToTime")
	_pf_docdb_true(name, "UseLatestRestorableTime")
}
''',
     tpl(restore({"RestoreToTime": "2026-09-22T00:00:00Z", "UseLatestRestorableTime": True})),
     tpl(restore({"UseLatestRestorableTime": True})),
     api="RestoreDBClusterToPointInTime")

# 13 serverless v2 capacities in 0.5 DCU steps
rule("pf-docdb-serverless-half-step", "pf-ddb-serverless-half-step", ["AWS::DocDB::DBCluster"],
     "Serverless capacity must be a multiple of 0.5 DCU", API_SV2,
     target("CreateDBCluster", "InvalidParameterValue: Serverless v2 capacity value 8.3 is not valid. It must be a multiple of 0.5.", "MinCapacity 8.3; 8.5 control accepted"),
     HEADER + r'''_pf_docdbshs_url := "''' + API_SV2 + r'''"

_pf_docdbshs_bad(n) if {
	f := n * 2
	f != round(f)
}

violation contains make_diag_full("pf-docdb-serverless-half-step", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v is not a multiple of 0.5 (\"Serverless v2 capacity value 8.3 is not valid. It must be a multiple of 0.5.\")", [n]),
	"Round the capacity to a multiple of 0.5",
	_pf_docdbshs_url) if {
	some name in _pf_docdb_clusters
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	_pf_docdbshs_bad(n)
}

violation contains make_diag_full("pf-docdb-serverless-half-step", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MaxCapacity",
	sprintf("MaxCapacity %v is not a multiple of 0.5 (\"Serverless v2 capacity value 8.3 is not valid. It must be a multiple of 0.5.\")", [n]),
	"Round the capacity to a multiple of 0.5",
	_pf_docdbshs_url) if {
	some name in _pf_docdb_clusters
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	_pf_docdbshs_bad(n)
}
''',
     tpl(cluster({"ServerlessV2ScalingConfiguration": {"MinCapacity": 8.3, "MaxCapacity": 16}})),
     tpl(cluster({"ServerlessV2ScalingConfiguration": {"MinCapacity": 8.5, "MaxCapacity": 16}})))

# 14 serverless v2 MinCapacity <= MaxCapacity
rule("pf-docdb-serverless-min-le-max", "pf-ddb-serverless-min-le-max", ["AWS::DocDB::DBCluster"],
     "Serverless MinCapacity must not exceed MaxCapacity", API_SV2,
     target("CreateDBCluster", "InvalidParameterValue: Serverless v2 minimum capacity must be less than or equal to maximum capacity", "MinCapacity 8.5 / MaxCapacity 8; 8 / 8 control accepted"),
     HEADER + r'''violation contains make_diag_full("pf-docdb-serverless-min-le-max", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v exceeds MaxCapacity %v (\"Serverless v2 minimum capacity must be less than or equal to maximum capacity\")", [mn, mx]),
	"Keep MinCapacity <= MaxCapacity",
	"''' + API_SV2 + r'''") if {
	some name in _pf_docdb_clusters
	mn := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	mx := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	mn > mx
}
''',
     tpl(cluster({"ServerlessV2ScalingConfiguration": {"MinCapacity": 8.5, "MaxCapacity": 8}})),
     tpl(cluster({"ServerlessV2ScalingConfiguration": {"MinCapacity": 8, "MaxCapacity": 8}})))

# 15 StorageType iopt1 needs engine 5.0+
rule("pf-docdb-storage-type-engine-version", "pf-ddb-storage-type-engine-version", ["AWS::DocDB::DBCluster"],
     "StorageType iopt1 requires engine version 5.0 or later", DOC_CLASSES,
     target("CreateDBCluster", "InvalidParameterCombination: The iopt1 storage type isn't supported for the 4.0.0 DB engine version.", "iopt1 + 4.0.0; iopt1 + 5.0.0 control accepted"),
     HEADER + r'''# Only a literal EngineVersion with a numeric major is judged; an absent EngineVersion
# defaults to the latest major (iopt1-capable) and stays silent.
violation contains make_diag_full("pf-docdb-storage-type-engine-version", "ERROR", name,
	"Properties.StorageType",
	sprintf("StorageType iopt1 is not supported for engine version %s; DocumentDB needs 5.0 or later (\"The iopt1 storage type isn't supported for the 4.0.0 DB engine version.\")", [ver]),
	"Use EngineVersion 5.0.0 or later, or StorageType standard",
	"''' + DOC_CLASSES + r'''") if {
	some name in _pf_docdb_clusters
	st := _pf_docdb_lit(name, "Properties.StorageType")
	lower(st) == "iopt1"
	ver := _pf_docdb_lit(name, "Properties.EngineVersion")
	regex.match(`^[1-9][0-9]*(\.[0-9]+)*$`, ver)
	parts := split(ver, ".")
	major := to_number(parts[0])
	major < 5
}
''',
     tpl(cluster({"StorageType": "iopt1", "EngineVersion": "4.0.0"})),
     tpl(cluster({"StorageType": "iopt1", "EngineVersion": "5.0.0"})))

# 16 DBSubnetGroupName 'default' is reserved
rule("pf-docdb-subnet-group-name-not-default", "pf-ddb-subnet-group-name-not-default", ["AWS::DocDB::DBSubnetGroup"],
     "DBSubnetGroupName: default is reserved", CFN_SNG,
     target("CreateDBSubnetGroup", "InvalidParameterValue: Subnet group name default is reserved. Please specify another name."),
     HEADER + r'''violation contains make_diag_full("pf-docdb-subnet-group-name-not-default", "ERROR", name,
	"Properties.DBSubnetGroupName",
	"DBSubnetGroupName \"default\" is reserved (\"Subnet group name default is reserved. Please specify another name.\")",
	"Pick another subnet group name",
	"''' + CFN_SNG + r'''") if {
	some name in resources_of_type("AWS::DocDB::DBSubnetGroup")
	n := _pf_docdb_lit(name, "Properties.DBSubnetGroupName")
	lower(n) == "default"
}
''',
     tpl(subnet_group(["us-east-1a", "us-east-1b"], name="default")),
     tpl(subnet_group(["us-east-1a", "us-east-1b"], name="cdkpf-docdb-sng-pass")),
     api="CreateDBSubnetGroup")

# 17 subnet group must cover >= 2 AZs
rule("pf-docdb-subnet-group-two-az", "pf-ddb-subnet-group-two-az", ["AWS::DocDB::DBSubnetGroup", "AWS::EC2::Subnet"],
     "A DB subnet group must cover at least two Availability Zones", CFN_SNG,
     target("CreateDBSubnetGroup", "DBSubnetGroupDoesNotCoverEnoughAZs: The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. Current AZ coverage: us-east-1a. Add subnets to cover at least 2 AZs.", "2 subnets in us-east-1a; us-east-1a + us-east-1b control accepted"),
     HEADER + r'''# Judged only when every subnet is a same-template AWS::EC2::Subnet with a literal
# AvailabilityZone; Fn::Select/Fn::GetAZs zones and imported subnet ids stay silent.
_pf_docdb2az_ref(v) := v if is_string(v)

_pf_docdb2az_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}

_pf_docdb2az_az(v) := az if {
	sub := _pf_docdb2az_ref(v)
	sub in resources_of_type("AWS::EC2::Subnet")
	az := resolve(sub, "Properties.AvailabilityZone")
	is_string(az)
	not input.resources[az]
}

_pf_docdb2az_azs(name) := [az |
	some s in flatten_list(name, "Properties.SubnetIds")
	az := _pf_docdb2az_az(s.value)
]

violation contains make_diag_full("pf-docdb-subnet-group-two-az", "ERROR", name,
	"Properties.SubnetIds",
	sprintf("All %v subnets of the DB subnet group sit in %s; DocumentDB needs at least 2 Availability Zones (\"The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement ... Add subnets to cover at least 2 AZs.\")", [count(subs), az]),
	"Add a subnet from a second Availability Zone",
	"''' + CFN_SNG + r'''") if {
	some name in resources_of_type("AWS::DocDB::DBSubnetGroup")
	subs := flatten_list(name, "Properties.SubnetIds")
	count(subs) > 0
	azs := _pf_docdb2az_azs(name)
	count(azs) == count(subs)
	distinct := {x | some x in azs}
	count(distinct) == 1
	some az in distinct
}
''',
     tpl(subnet_group(["us-east-1a", "us-east-1a"])),
     tpl(subnet_group(["us-east-1a", "us-east-1b"])),
     api="CreateDBSubnetGroup")

# 18 MasterUsername must start with a letter (UNNAMED: API names the property only)
rule("pf-docdb-username-first-char-letter", "pf-ddb-username-first-char-letter", ["AWS::DocDB::DBCluster"],
     "MasterUsername must start with a letter", API_CLUSTER,
     '%s: CreateDBCluster MasterUsername 1pfadmin -> "InvalidParameterValue: Invalid master user name" (#66 phase B UNNAMED: the API names the property, not the rule; control benchuser accepted); bench: PENDING' % PROBE,
     HEADER + r'''# Claim scope: first character only (the API doc also says 1-63 letters or numbers, but only
# the leading digit was probed; the charset and length stay silent).
violation contains make_diag_full("pf-docdb-username-first-char-letter", "ERROR", name,
	"Properties.MasterUsername",
	sprintf("MasterUsername '%s' does not start with a letter; DocumentDB rejects it (\"Invalid master user name\")", [u]),
	"Start the master user name with a letter",
	"''' + API_CLUSTER + r'''") if {
	some name in _pf_docdb_clusters
	u := _pf_docdb_lit(name, "Properties.MasterUsername")
	not regex.match(`^[A-Za-z]`, u)
}
''',
     tpl(cluster({"MasterUsername": "1benchuser"})),
     tpl(cluster({"MasterUsername": "benchuser"})))

# ---------------------------------------------------------------- lib

LIB = HEADER + r'''# DocumentDB ルールの共有ヘルパー。不在の証明は input.resources 側でしかできない
# （resolve() はキー不在と未解決トークンの両方で undefined になる、AGENTS.md 参照）ので、
# 「プロパティが書かれているか」は必ず _pf_docdb_has を通す。診断は出さない（BUNDLED_LIBS）。

_pf_docdb_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_docdb_get(name, k) := v if {
	v := object.get(_pf_docdb_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

_pf_docdb_has(name, k) if {
	_pf_docdb_get(name, k)
}

# 文書に true と書かれている場合だけ真（未解決トークンは対象外）。
_pf_docdb_true(name, k) if _pf_docdb_get(name, k) == true

_pf_docdb_true(name, k) if _pf_docdb_get(name, k) == "true"

_pf_docdb_clusters := resources_of_type("AWS::DocDB::DBCluster")

# ユーザーが書いたリテラル文字列。Ref/GetAtt は論理 ID に解決されるので弾く。
_pf_docdb_lit(name, path) := v if {
	v := resolve(name, path)
	is_string(v)
	not input.resources[v]
}

# "HH:MM" -> 分（0-1439）。to_number は先頭ゼロを拒む（to_number("03") は undefined）ので
# 桁表と substring で組む。書式が違えば undefined。
_pf_docdb_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_docdb_hm(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_docdb_digit[substring(t, 0, 1)] * 10) + _pf_docdb_digit[substring(t, 1, 1)]
	mi := (_pf_docdb_digit[substring(t, 3, 1)] * 10) + _pf_docdb_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

_pf_docdb_day := {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

# "ddd:HH:MM" -> 週の分（0-10079）。曜日は大小無視。書式が違えば undefined。
_pf_docdb_dhm(t) := m if {
	is_string(t)
	p := split(lower(t), ":")
	count(p) == 3
	d := _pf_docdb_day[p[0]]
	hm := _pf_docdb_hm(sprintf("%s:%s", [p[1], p[2]]))
	m := (d * 1440) + hm
}
'''

EXCEPTIONS = {
    "pf-docdb-serverless-min-le-max": "MinCapacity / MaxCapacity は 0.5 DCU 刻みなので、最も近い違反値の差は 0.5 であって 1 ではない（fail は 8.5/8 に乗せてある）。機械チェックは整数 1 の差を要求する。pass は 8/8 で限界そのものに乗っている（pf-rds-serverless-v2-capacity と同型）",
}

# ---------------------------------------------------------------- write


def yaml_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def meta(r):
    return "\n".join([
        "id: %s" % r["id"],
        "service: docdb",
        "resourceTypes: [%s]" % ", ".join(r["types"]),
        "severity: ERROR",
        "title: %s" % yaml_str(r["title"]),
        "constraintSource: %s" % r["source"],
        "upstream: none",
        "benchRegion: us-east-1",
        "repro:",
        "  method: real-deploy",
        "  evidence: %s" % yaml_str(r["evidence"]),
        "addedOn: %s" % ADDED,
    ]) + "\n"


def main():
    sdir = os.path.join(ROOT, "rules", "docdb")
    if os.path.isdir(sdir):
        for d in os.listdir(sdir):
            if d.startswith("pf-docdb-"):
                shutil.rmtree(os.path.join(sdir, d))
    os.makedirs(sdir, exist_ok=True)
    ids = set()
    for r in RULES:
        assert r["id"] not in ids, r["id"]
        ids.add(r["id"])
        d = os.path.join(sdir, r["id"])
        os.makedirs(os.path.join(d, "templates"))
        with open(os.path.join(d, "rule.rego"), "w") as f:
            f.write(r["rego"])
        with open(os.path.join(d, "meta.yaml"), "w") as f:
            f.write(meta(r))
        for kind, t in (("fail", r["fail"]), ("pass", r["pass_"])):
            with open(os.path.join(d, "templates", "%s.template.json" % kind), "w") as f:
                json.dump(t, f, indent=2)
                f.write("\n")
    with open(os.path.join(ROOT, "rules", "_lib", "docdb.rego"), "w") as f:
        f.write(LIB)
    # boundary exceptions: replace the pf-docdb- lines, keep everything else
    exc = os.path.join(ROOT, "rules", "_boundary-exceptions.txt")
    with open(exc) as f:
        lines = [l for l in f.read().split("\n") if not l.startswith("pf-docdb-")]
    while lines and lines[-1] == "":
        lines.pop()
    for k in sorted(EXCEPTIONS):
        lines.append("%s  %s" % (k, EXCEPTIONS[k]))
    with open(exc, "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(SURVEY, "pending-docdb.txt"), "w") as f:
        f.write("\n".join(r["id"] for r in RULES) + "\n")
    with open(os.path.join(SURVEY, "docdb-id-map.md"), "w") as f:
        f.write("| candidate | rule id | class |\n|---|---|---|\n")
        for r in RULES:
            cls = "BENCH" if r["evidence"].startswith("api-probe: none") else ("UNNAMED" if "UNNAMED" in r["evidence"] else "TARGET")
            f.write("| `%s` | `%s` | %s |\n" % (r["cand"], r["id"], cls))
    print("wrote %d rules to %s" % (len(RULES), sdir))


if __name__ == "__main__":
    main()
