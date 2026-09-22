#!/usr/bin/env python3
"""#66 C3: Neptune (rules/neptune) + Neptune Analytics (rules/neptunegraph) のジェネレータ。
rule.rego / meta.yaml / templates/{fail,pass}.template.json と rules/_lib/neptune.rego を吐く。
直しはここに入れて再生成する（1 本ずつ手で書かない）。
"""
import json
import os
import shutil
import sys

WT = os.environ.get("PF_WT", "/home/user/wt-neptune")
ADDED = "2026-09-22"
PROBE = "api-probe 2026-09-15 us-east-1"
BENCH_NONE = "api-probe: none (#66 phase B BENCH); bench: PENDING 2026-09-22 us-east-1"
DEL = {"DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete"}

U_APICL = "https://docs.aws.amazon.com/neptune/latest/userguide/api-clusters.html"
U_APIIN = "https://docs.aws.amazon.com/neptune/latest/userguide/api-instances.html"
U_CL = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html"
U_CPG = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbclusterparametergroup.html"
U_SLS = "https://docs.aws.amazon.com/neptune/latest/userguide/neptune-serverless-capacity-scaling.html"
U_SSC = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster-serverlessscalingconfiguration.html"
U_GC = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-globalcluster.html"
U_SG = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbsubnetgroup.html"
U_NG = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptunegraph-graph.html"
U_NGAPI = "https://docs.aws.amazon.com/neptune-analytics/latest/apiref/API_CreateGraph.html"
U_PGE = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptunegraph-privategraphendpoint.html"

HEAD = "package cdk_preflight\n\nimport rego.v1\n\n"

# エンジン版: 2026-09-15 の B プローブは 1.3 系で通った（"Please use ... neptune1.3"）。
# 実機で "engine version not found" が出たら describe-db-engine-versions --engine neptune の値に差し替える。
ENGINE_VERSION = "1.3.4.0"


def probe(call, msg):
    return f'{PROBE}: {call} -> "{msg}" (#66 phase B); bench: PENDING'


def cluster(**p):
    return {"Type": "AWS::Neptune::DBCluster", **DEL, "Properties": p}


def instance(**p):
    return {"Type": "AWS::Neptune::DBInstance", **DEL, "Properties": p}


def graph(**p):
    return {"Type": "AWS::NeptuneGraph::Graph", **DEL,
            "Properties": {"ProvisionedMemory": 16, "ReplicaCount": 0, "DeletionProtection": False, **p}}


VPC = {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}}
VPC2 = {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.1.0.0/16"}}


def subnet(vpc, cidr, az):
    return {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": vpc}, "CidrBlock": cidr, "AvailabilityZone": az}}


# 既存フィクスチャ（pf-kms-alias-name の pass）と同じ最小形。KeyPolicy 省略＝既定のルート権限。
KMS_KEY = {"Type": "AWS::KMS::Key", **DEL, "Properties": {"PendingWindowInDays": 7}}
KEY_ARN = {"Fn::GetAtt": ["Key", "Arn"]}

LIB = HEAD + r'''# Neptune / Neptune Analytics ルールの共有ヘルパー。診断は出さない（BUNDLED_LIBS）。
# 不在の証明は input.resources 側でしかできない（resolve() はキー不在と未解決トークンの
# 両方で undefined、AGENTS.md 参照）ので、「書かれているか」は _pf_neptunelib_has を通す。

_pf_neptunelib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_neptunelib_get(name, k) := v if {
	v := object.get(_pf_neptunelib_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

# 値が false のキーも「書かれている」。素の関数呼び出しを文にすると戻り値 false で
# 本体が失敗する（2026-09-22 実測: StorageEncrypted: false が「不在」に見えた）ので比較で書く。
_pf_neptunelib_has(name, k) if {
	object.get(_pf_neptunelib_props(name), k, "__pf_absent") != "__pf_absent"
}

# 文書に true / false と書かれている場合だけ真（未解決トークンはどちらでもない）。
_pf_neptunelib_true(name, k) if _pf_neptunelib_get(name, k) == true

_pf_neptunelib_true(name, k) if _pf_neptunelib_get(name, k) == "true"

_pf_neptunelib_false(name, k) if _pf_neptunelib_get(name, k) == false

_pf_neptunelib_false(name, k) if _pf_neptunelib_get(name, k) == "false"

# "hh:mm" -> 分。to_number は先頭ゼロを受けない（AGENTS.md）ので桁表で組む。
_pf_neptunelib_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_neptunelib_hhmm(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_neptunelib_digit[substring(t, 0, 1)] * 10) + _pf_neptunelib_digit[substring(t, 1, 1)]
	mi := (_pf_neptunelib_digit[substring(t, 3, 1)] * 10) + _pf_neptunelib_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

# "hh:mm-hh:mm"（バックアップ窓）の始点 / 終点（分）。書式外は undefined。
_pf_neptunelib_wstart(w) := m if {
	is_string(w)
	p := split(w, "-")
	count(p) == 2
	m := _pf_neptunelib_hhmm(p[0])
}

_pf_neptunelib_wend(w) := m if {
	is_string(w)
	p := split(w, "-")
	count(p) == 2
	m := _pf_neptunelib_hhmm(p[1])
}

# "ddd:hh:mm"（メンテナンス窓の片側）-> 月曜 00:00 からの分。
_pf_neptunelib_day := {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

_pf_neptunelib_wkmin(t) := m if {
	is_string(t)
	p := split(lower(t), ":")
	count(p) == 3
	d := _pf_neptunelib_day[p[0]]
	hm := _pf_neptunelib_hhmm(sprintf("%s:%s", [p[1], p[2]]))
	m := (d * 1440) + hm
}
'''

RULES = []


def rule(id, service, types, title, source, evidence, rego, fail, pass_):
    RULES.append(dict(id=id, service=service, types=types, title=title, source=source,
                      evidence=evidence, rego=HEAD + rego, fail=fail, pass_=pass_))


# ---------------------------------------------------------------- neptune
rule("pf-neptune-backup-maintenance-overlap", "neptune", ["AWS::Neptune::DBCluster"],
     "The backup window and the maintenance window must not overlap", U_APICL,
     probe("CreateDBCluster", "InvalidParameterValue: The backup window and maintenance window must not overlap."),
     r'''# 日次のバックアップ窓と週次のメンテナンス窓は、時刻の区間が交われば重なる。見るのは
# 両窓が整形式で日付をまたがず、メンテナンス窓が同じ曜日で閉じる形だけ（under-claim）。
violation contains make_diag_full("pf-neptune-backup-maintenance-overlap", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow %s overlaps PreferredMaintenanceWindow %s; Neptune rejects the pair (\"The backup window and maintenance window must not overlap.\")", [bw, mw]),
	"Separate the two windows in time",
	"''' + U_APICL + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	bw := resolve(name, "Properties.PreferredBackupWindow")
	bs := _pf_neptunelib_wstart(bw)
	be := _pf_neptunelib_wend(bw)
	bs < be
	mw := resolve(name, "Properties.PreferredMaintenanceWindow")
	is_string(mw)
	mp := split(lower(mw), "-")
	count(mp) == 2
	m1 := split(mp[0], ":")
	m2 := split(mp[1], ":")
	count(m1) == 3
	count(m2) == 3
	m1[0] == m2[0]
	ms := _pf_neptunelib_hhmm(sprintf("%s:%s", [m1[1], m1[2]]))
	me := _pf_neptunelib_hhmm(sprintf("%s:%s", [m2[1], m2[2]]))
	ms < me
	bs < me
	ms < be
}
''',
     {"C": cluster(PreferredBackupWindow="07:00-08:00", PreferredMaintenanceWindow="mon:07:59-mon:08:59")},
     {"C": cluster(PreferredBackupWindow="07:00-08:00", PreferredMaintenanceWindow="mon:08:00-mon:09:00")})

rule("pf-neptune-backup-retention-range", "neptune", ["AWS::Neptune::DBCluster"],
     "BackupRetentionPeriod must be at most 35 days", U_APICL,
     probe("CreateDBCluster", "InvalidParameterValue: Invalid backup retention period: 36. Retention period must be between 1 and 35."),
     r'''# 下限 1 は同梱エンジンのスキーマが F3034 で止める（2026-09-22 guard）ので、上限だけを見る。
violation contains make_diag_full("pf-neptune-backup-retention-range", "ERROR", name,
	"Properties.BackupRetentionPeriod",
	sprintf("BackupRetentionPeriod %v exceeds 35 days (\"Invalid backup retention period: 36. Retention period must be between 1 and 35.\")", [n]),
	"Use a retention period of 35 days or less",
	"''' + U_APICL + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	n := to_number(resolve(name, "Properties.BackupRetentionPeriod"))
	n > 35
}
''',
     {"C": cluster(BackupRetentionPeriod=36)},
     {"C": cluster(BackupRetentionPeriod=35)})

rule("pf-neptune-backup-window-duration", "neptune", ["AWS::Neptune::DBCluster"],
     "The backup window must be at least 30 minutes", U_APICL,
     probe("CreateDBCluster", "InvalidParameterValue: Backup window must be at least 30 minutes."),
     r'''violation contains make_diag_full("pf-neptune-backup-window-duration", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' spans only %v minutes; Neptune requires at least 30 (\"Backup window must be at least 30 minutes.\")", [w, d]),
	"Widen the backup window to 30 minutes or more",
	"''' + U_APICL + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	w := resolve(name, "Properties.PreferredBackupWindow")
	s := _pf_neptunelib_wstart(w)
	e := _pf_neptunelib_wend(w)
	d := ((e - s) + 1440) % 1440
	d < 30
}
''',
     {"C": cluster(PreferredBackupWindow="07:00-07:29")},
     {"C": cluster(PreferredBackupWindow="07:00-07:30")})

rule("pf-neptune-backup-window-format", "neptune", ["AWS::Neptune::DBCluster"],
     "PreferredBackupWindow must be hh24:mi-hh24:mi (UTC)", U_APICL,
     probe("CreateDBCluster", "InvalidParameterValue: Invalid backup window time '0700' specified. Should be specified as a time hh24:mi (24H Clock UTC). Example: 03:15"),
     r'''violation contains make_diag_full("pf-neptune-backup-window-format", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is not hh24:mi-hh24:mi (24H clock UTC); Neptune rejects it (\"Invalid backup window time '0700' specified. Should be specified as a time hh24:mi (24H Clock UTC). Example: 03:15\")", [w]),
	"Use the hh24:mi-hh24:mi form, e.g. 03:00-04:00",
	"''' + U_APICL + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	w := resolve(name, "Properties.PreferredBackupWindow")
	is_string(w)
	not regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`, w)
}
''',
     {"C": cluster(PreferredBackupWindow="0700-0730")},
     {"C": cluster(PreferredBackupWindow="07:00-07:30")})

rule("pf-neptune-cpg-family-engine-version", "neptune",
     ["AWS::Neptune::DBCluster", "AWS::Neptune::DBClusterParameterGroup"],
     "The cluster parameter group family must match the cluster engine version", U_CPG,
     probe("CreateDBCluster", "InvalidParameterCombination: The Parameter Group pf66-pg12 with DBParameterGroupFamily neptune1.2 cannot be used for this instance. Please use a Parameter Group with DBParameterGroupFamily neptune1.3"),
     r'''# 1.0.x / 1.1.x は neptune1、1.2.0.0 以降は neptune1.<minor>（CFN の Family の説明）。
# 版が書かれていない（既定＝最新）クラスタや Ref で渡された版は判定しない。
_pf_nepcpg_want(v) := "neptune1" if {
	is_string(v)
	regex.match(`^1\.[01]\.`, v)
}

_pf_nepcpg_want(v) := sprintf("neptune1.%s", [p[1]]) if {
	is_string(v)
	regex.match(`^1\.([2-9]|[1-9][0-9]+)\.`, v)
	p := split(v, ".")
}

violation contains make_diag_full("pf-neptune-cpg-family-engine-version", "ERROR", name,
	"Properties.DBClusterParameterGroupName",
	sprintf("Cluster parameter group %v has Family %v, but EngineVersion %v needs %v (\"The Parameter Group ... with DBParameterGroupFamily neptune1.2 cannot be used for this instance. Please use a Parameter Group with DBParameterGroupFamily neptune1.3\")", [pg, fam, v, want]),
	"Match the parameter group family to the engine version",
	"''' + U_CPG + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	pg := resolve(name, "Properties.DBClusterParameterGroupName")
	is_string(pg)
	input.resources[pg].resourceType == "AWS::Neptune::DBClusterParameterGroup"
	f0 := resolve(pg, "Properties.Family")
	is_string(f0)
	fam := lower(f0)
	v := resolve(name, "Properties.EngineVersion")
	want := _pf_nepcpg_want(v)
	fam != want
}
''',
     {"C": cluster(EngineVersion=ENGINE_VERSION, DBClusterParameterGroupName={"Ref": "PG"}),
      "PG": {"Type": "AWS::Neptune::DBClusterParameterGroup", "Properties": {
          "Family": "neptune1.2", "Description": "cdkpf", "Parameters": {"neptune_enable_audit_log": "0"}}}},
     {"C": cluster(EngineVersion=ENGINE_VERSION, DBClusterParameterGroupName={"Ref": "PG"}),
      "PG": {"Type": "AWS::Neptune::DBClusterParameterGroup", "Properties": {
          "Family": "neptune1.3", "Description": "cdkpf", "Parameters": {"neptune_enable_audit_log": "0"}}}})

rule("pf-neptune-db-serverless-needs-scaling-config", "neptune",
     ["AWS::Neptune::DBInstance", "AWS::Neptune::DBCluster"],
     "A db.serverless instance needs a cluster with ServerlessScalingConfiguration", U_SLS,
     BENCH_NONE,
     r'''# クロスリソース: インスタンスが db.serverless なら、同じテンプレートのクラスタは
# ServerlessScalingConfiguration を持っていなければならない。クラスタが import
# されている（Ref 先がテンプレートに無い）場合は判定しない。
violation contains make_diag_full("pf-neptune-db-serverless-needs-scaling-config", "ERROR", name,
	"Properties.DBInstanceClass",
	sprintf("DBInstanceClass is db.serverless but cluster %v declares no ServerlessScalingConfiguration; Neptune rejects the instance at create time", [cl]),
	"Add ServerlessScalingConfiguration (MinCapacity/MaxCapacity) to the DB cluster",
	"''' + U_SLS + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBInstance")
	c := resolve(name, "Properties.DBInstanceClass")
	is_string(c)
	lower(c) == "db.serverless"
	cl := resolve(name, "Properties.DBClusterIdentifier")
	is_string(cl)
	input.resources[cl].resourceType == "AWS::Neptune::DBCluster"
	not _pf_neptunelib_has(cl, "ServerlessScalingConfiguration")
}
''',
     {"C": cluster(), "I": instance(DBClusterIdentifier={"Ref": "C"}, DBInstanceClass="db.serverless")},
     {"C": cluster(ServerlessScalingConfiguration={"MinCapacity": 1, "MaxCapacity": 2.5}),
      "I": instance(DBClusterIdentifier={"Ref": "C"}, DBInstanceClass="db.serverless")})

rule("pf-neptune-globalcluster-source-exclusive", "neptune", ["AWS::Neptune::GlobalCluster"],
     "SourceDBClusterIdentifier excludes Engine, EngineVersion and StorageEncrypted", U_GC,
     probe("CreateGlobalCluster", "InvalidParameterCombination: When creating global cluster from existing db cluster, value for engineName should not be specified since it will be inherited from source cluster"),
     r'''# 既存クラスタから作る global cluster は Engine / EngineVersion / StorageEncrypted を
# ソースから継承するので、書くと拒否される（値は見ない。書かれているかだけ）。
_pf_nepgcx_inherited := {"Engine", "EngineVersion", "StorageEncrypted"}

violation contains make_diag_full("pf-neptune-globalcluster-source-exclusive", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s is set together with SourceDBClusterIdentifier; Neptune inherits it from the source cluster and rejects the pair (\"When creating global cluster from existing db cluster, value for engineName should not be specified since it will be inherited from source cluster\")", [k]),
	"Remove Engine, EngineVersion and StorageEncrypted when SourceDBClusterIdentifier is set",
	"''' + U_GC + r'''") if {
	some name in resources_of_type("AWS::Neptune::GlobalCluster")
	_pf_neptunelib_has(name, "SourceDBClusterIdentifier")
	some k in _pf_nepgcx_inherited
	_pf_neptunelib_has(name, k)
}
''',
     {"G": {"Type": "AWS::Neptune::GlobalCluster", **DEL, "Properties": {
         "SourceDBClusterIdentifier": "arn:aws:rds:us-east-1:123456789012:cluster:pf66-src", "Engine": "neptune"}}},
     {"G": {"Type": "AWS::Neptune::GlobalCluster", **DEL, "Properties": {"Engine": "neptune", "DeletionProtection": False}}})

rule("pf-neptune-instance-az-region", "neptune", ["AWS::Neptune::DBInstance"],
     "The instance AvailabilityZone must be in the deployment region", U_APIIN,
     BENCH_NONE,
     r'''# レンズ 3: AZ 名のリージョン部がデプロイ先と違う。deploy_region は enforce プラグインが
# 焼き込むので、未注入（リージョン未確定）なら判定しない。AZ ID（use1-az1）は対象外。
violation contains make_diag_full("pf-neptune-instance-az-region", "ERROR", name,
	"Properties.AvailabilityZone",
	sprintf("AvailabilityZone %s is in %s but the stack deploys to %s; Neptune rejects the instance at create time", [az, region, data.cdk_preflight.deploy_region]),
	"Pick an Availability Zone of the deployment region",
	"''' + U_APIIN + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBInstance")
	az := resolve(name, "Properties.AvailabilityZone")
	is_string(az)
	regex.match(`^[a-z]{2}(-gov)?-[a-z]+-[0-9][a-z]$`, az)
	region := substring(az, 0, count(az) - 1)
	region != data.cdk_preflight.deploy_region
}
''',
     {"C": cluster(), "I": instance(DBClusterIdentifier={"Ref": "C"}, DBInstanceClass="db.t4g.medium", AvailabilityZone="us-west-2a")},
     {"C": cluster(), "I": instance(DBClusterIdentifier={"Ref": "C"}, DBInstanceClass="db.t4g.medium", AvailabilityZone="us-east-1a")})

rule("pf-neptune-kms-requires-storage-encrypted", "neptune", ["AWS::Neptune::DBCluster"],
     "KmsKeyId requires StorageEncrypted: true", U_CL,
     probe("CreateDBCluster", "InvalidParameterCombination: You cannot specify KMS key for unencrypted clusters."),
     r'''# StorageEncrypted が無い（既定 false）か false と書かれているのに KmsKeyId がある。
# スナップショット / ソースクラスタからの復元は暗号化を継承するので判定しない。
_pf_nepkms_unencrypted(name) if not _pf_neptunelib_has(name, "StorageEncrypted")

_pf_nepkms_unencrypted(name) if _pf_neptunelib_false(name, "StorageEncrypted")

violation contains make_diag_full("pf-neptune-kms-requires-storage-encrypted", "ERROR", name,
	"Properties.KmsKeyId",
	"KmsKeyId is set but StorageEncrypted is not true; Neptune rejects the cluster (\"You cannot specify KMS key for unencrypted clusters.\")",
	"Set StorageEncrypted: true (or drop KmsKeyId)",
	"''' + U_CL + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	_pf_neptunelib_has(name, "KmsKeyId")
	not _pf_neptunelib_has(name, "SnapshotIdentifier")
	not _pf_neptunelib_has(name, "SourceDBClusterIdentifier")
	_pf_nepkms_unencrypted(name)
}
''',
     {"Key": KMS_KEY, "C": cluster(KmsKeyId=KEY_ARN), "C2": cluster(KmsKeyId=KEY_ARN, StorageEncrypted=False)},
     {"Key": KMS_KEY, "C": cluster(KmsKeyId=KEY_ARN, StorageEncrypted=True)})

rule("pf-neptune-maintenance-window-duration", "neptune", ["AWS::Neptune::DBCluster", "AWS::Neptune::DBInstance"],
     "The maintenance window must be at least 30 minutes", U_APICL,
     probe("CreateDBCluster", "InvalidParameterValue: Maintenance window must be at least 30 minutes."),
     r'''_pf_nepmwd_types := {"AWS::Neptune::DBCluster", "AWS::Neptune::DBInstance"}

violation contains make_diag_full("pf-neptune-maintenance-window-duration", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("PreferredMaintenanceWindow '%s' spans only %v minutes; Neptune requires at least 30 (\"Maintenance window must be at least 30 minutes.\")", [w, d]),
	"Widen the maintenance window to 30 minutes or more",
	"''' + U_APICL + r'''") if {
	some t in _pf_nepmwd_types
	some name in resources_of_type(t)
	w := resolve(name, "Properties.PreferredMaintenanceWindow")
	is_string(w)
	p := split(w, "-")
	count(p) == 2
	s := _pf_neptunelib_wkmin(p[0])
	e := _pf_neptunelib_wkmin(p[1])
	d := ((e - s) + 10080) % 10080
	d < 30
}
''',
     {"C": cluster(PreferredMaintenanceWindow="mon:07:00-mon:07:29")},
     {"C": cluster(PreferredMaintenanceWindow="mon:07:00-mon:07:30")})

rule("pf-neptune-port-range", "neptune", ["AWS::Neptune::DBCluster"],
     "DBPort must be within 1150-65535", U_CL,
     probe("CreateDBCluster", "InvalidParameterValue: Invalid endpoint port 1149. Valid range is: 1150-65535"),
     r'''_pf_nepport_out(n) if n < 1150

_pf_nepport_out(n) if n > 65535

violation contains make_diag_full("pf-neptune-port-range", "ERROR", name,
	"Properties.DBPort",
	sprintf("DBPort %v is outside 1150-65535 (\"Invalid endpoint port 1149. Valid range is: 1150-65535\")", [n]),
	"Pick a port between 1150 and 65535",
	"''' + U_CL + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	n := to_number(resolve(name, "Properties.DBPort"))
	_pf_nepport_out(n)
}
''',
     {"C": cluster(DBPort=1149), "C2": cluster(DBPort=65536)},
     {"C": cluster(DBPort=1150), "C2": cluster(DBPort=65535)})

rule("pf-neptune-serverless-half-step", "neptune", ["AWS::Neptune::DBCluster"],
     "Serverless capacities must be multiples of 0.5 NCU", U_SSC,
     probe("CreateDBCluster", "InvalidParameterValue: Serverless v2 capacity value 4.3 is not valid. It must be a multiple of 0.5."),
     r'''_pf_nepstep_bad(n) if {
	f := n * 2
	f != round(f)
}

_pf_nepstep_keys := {"MinCapacity", "MaxCapacity"}

violation contains make_diag_full("pf-neptune-serverless-half-step", "ERROR", name,
	sprintf("Properties.ServerlessScalingConfiguration.%s", [k]),
	sprintf("%s %v is not a multiple of 0.5 NCU (\"Serverless v2 capacity value 4.3 is not valid. It must be a multiple of 0.5.\")", [k, n]),
	"Round the capacity to a multiple of 0.5",
	"''' + U_SSC + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	some k in _pf_nepstep_keys
	n := to_number(resolve(name, sprintf("Properties.ServerlessScalingConfiguration.%s", [k])))
	_pf_nepstep_bad(n)
}
''',
     {"C": cluster(ServerlessScalingConfiguration={"MinCapacity": 4.3, "MaxCapacity": 8})},
     {"C": cluster(ServerlessScalingConfiguration={"MinCapacity": 4.5, "MaxCapacity": 8})})

rule("pf-neptune-serverless-min-le-max", "neptune", ["AWS::Neptune::DBCluster"],
     "Serverless MinCapacity must not exceed MaxCapacity", U_SLS,
     probe("CreateDBCluster", "InvalidParameterValue: Serverless v2 minimum capacity must be less than or equal to maximum capacity"),
     r'''violation contains make_diag_full("pf-neptune-serverless-min-le-max", "ERROR", name,
	"Properties.ServerlessScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v exceeds MaxCapacity %v (\"Serverless v2 minimum capacity must be less than or equal to maximum capacity\")", [mn, mx]),
	"Keep MinCapacity <= MaxCapacity",
	"''' + U_SLS + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	mn := to_number(resolve(name, "Properties.ServerlessScalingConfiguration.MinCapacity"))
	mx := to_number(resolve(name, "Properties.ServerlessScalingConfiguration.MaxCapacity"))
	mn > mx
}
''',
     {"C": cluster(ServerlessScalingConfiguration={"MinCapacity": 3, "MaxCapacity": 2.5})},
     {"C": cluster(ServerlessScalingConfiguration={"MinCapacity": 2.5, "MaxCapacity": 2.5})})

rule("pf-neptune-subnet-group-two-az", "neptune", ["AWS::Neptune::DBSubnetGroup", "AWS::EC2::Subnet"],
     "A DB subnet group must cover at least two Availability Zones", U_SG,
     probe("CreateDBSubnetGroup", "DBSubnetGroupDoesNotCoverEnoughAZs: The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. Current AZ coverage: us-east-1a. Add subnets to cover at least 2 AZs."),
     r'''# 全 SubnetIds が同じテンプレートの AWS::EC2::Subnet で AZ がリテラルのときだけ判定する。
# Fn::GetAZs / Fn::Select で AZ を選ぶ CDK の Vpc や import した subnet ID は解決できないので
# 対象外（under-claim）。配列要素は Properties.SubnetIds.<i> で解決する（AGENTS.md）。
_pf_nepsg_az(name, i) := az if {
	sref := resolve(name, sprintf("Properties.SubnetIds.%d", [i]))
	is_string(sref)
	input.resources[sref].resourceType == "AWS::EC2::Subnet"
	az := resolve(sref, "Properties.AvailabilityZone")
	is_string(az)
}

_pf_nepsg_azs(name) := [az |
	some s in flatten_list(name, "Properties.SubnetIds")
	az := _pf_nepsg_az(name, s.index)
]

_pf_nepsg_multi(name) if {
	azs := _pf_nepsg_azs(name)
	some az in azs
	count([x | some x in azs; x != az]) > 0
}

violation contains make_diag_full("pf-neptune-subnet-group-two-az", "ERROR", name,
	"Properties.SubnetIds",
	sprintf("SubnetIds covers only Availability Zone %s; Neptune requires at least two (\"The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. Current AZ coverage: us-east-1a. Add subnets to cover at least 2 AZs.\")", [azs[0]]),
	"Add a subnet in a second Availability Zone",
	"''' + U_SG + r'''") if {
	some name in resources_of_type("AWS::Neptune::DBSubnetGroup")
	ids := flatten_list(name, "Properties.SubnetIds")
	count(ids) > 0
	azs := _pf_nepsg_azs(name)
	count(azs) == count(ids)
	not _pf_nepsg_multi(name)
}
''',
     {"V": VPC, "S1": subnet("V", "10.0.0.0/24", "us-east-1a"), "S2": subnet("V", "10.0.1.0/24", "us-east-1a"),
      "SG": {"Type": "AWS::Neptune::DBSubnetGroup", "Properties": {"DBSubnetGroupDescription": "cdkpf", "SubnetIds": [{"Ref": "S1"}, {"Ref": "S2"}]}}},
     {"V": VPC, "S1": subnet("V", "10.0.0.0/24", "us-east-1a"), "S2": subnet("V", "10.0.1.0/24", "us-east-1b"),
      "SG": {"Type": "AWS::Neptune::DBSubnetGroup", "Properties": {"DBSubnetGroupDescription": "cdkpf", "SubnetIds": [{"Ref": "S1"}, {"Ref": "S2"}]}}})

# ---------------------------------------------------------------- neptunegraph
rule("pf-neptunegraph-graph-name-lowercase", "neptunegraph", ["AWS::NeptuneGraph::Graph"],
     "GraphName must be lowercase and must not start with g-", U_NGAPI,
     BENCH_NONE,
     r'''# API モデル（neptune-graph 2023-11-29 GraphName）: (?!g-)[a-z][a-z0-9]*(-[a-z0-9]+)*、1-63 文字。
# 長さ・先頭が英字・末尾/連続ハイフンは同梱エンジンのスキーマ（F3031 / F3033）が止める
# （2026-09-22 guard）。スキーマのパターンが通してしまう大文字と g- 接頭辞だけを見る。
_pf_ngname_lit(name) := g if {
	g := resolve(name, "Properties.GraphName")
	is_string(g)
	not input.resources[g]
}

violation contains make_diag_full("pf-neptunegraph-graph-name-lowercase", "ERROR", name,
	"Properties.GraphName",
	sprintf("GraphName '%s' contains uppercase letters; Neptune Analytics accepts only lowercase letters, digits and hyphens", [g]),
	"Use lowercase letters, digits and hyphens only",
	"''' + U_NGAPI + r'''") if {
	some name in resources_of_type("AWS::NeptuneGraph::Graph")
	g := _pf_ngname_lit(name)
	regex.match(`[A-Z]`, g)
}

violation contains make_diag_full("pf-neptunegraph-graph-name-lowercase", "ERROR", name,
	"Properties.GraphName",
	sprintf("GraphName '%s' starts with 'g-', which Neptune Analytics reserves for graph identifiers", [g]),
	"Pick a name that does not start with g-",
	"''' + U_NGAPI + r'''") if {
	some name in resources_of_type("AWS::NeptuneGraph::Graph")
	g := _pf_ngname_lit(name)
	startswith(g, "g-")
}
''',
     {"G": graph(GraphName="Pf66-name-upper"), "G2": graph(GraphName="g-pf66-name")},
     {"G": graph(GraphName="pf66-name-lower")})

rule("pf-neptunegraph-private-endpoint-subnet-vpc-match", "neptunegraph",
     ["AWS::NeptuneGraph::PrivateGraphEndpoint", "AWS::EC2::Subnet"],
     "PrivateGraphEndpoint SubnetIds must belong to its VpcId", U_PGE,
     BENCH_NONE,
     r'''# クロスリソース: SubnetIds の各要素が同じテンプレートの AWS::EC2::Subnet なら、その VpcId
# はエンドポイントの VpcId と同じでなければならない。Ref はどちらも論理 ID に解決される
# ので文字列で比べられる。import した subnet ID は解決できないので対象外。
violation contains make_diag_full("pf-neptunegraph-private-endpoint-subnet-vpc-match", "ERROR", name,
	sprintf("Properties.SubnetIds.%d", [s.index]),
	sprintf("Subnet %s belongs to VPC %s but the endpoint's VpcId is %s; Neptune Analytics rejects the endpoint at create time", [sref, sv, vpc]),
	"List only subnets of the VPC named in VpcId",
	"''' + U_PGE + r'''") if {
	some name in resources_of_type("AWS::NeptuneGraph::PrivateGraphEndpoint")
	vpc := resolve(name, "Properties.VpcId")
	is_string(vpc)
	some s in flatten_list(name, "Properties.SubnetIds")
	sref := resolve(name, sprintf("Properties.SubnetIds.%d", [s.index]))
	is_string(sref)
	input.resources[sref].resourceType == "AWS::EC2::Subnet"
	sv := resolve(sref, "Properties.VpcId")
	is_string(sv)
	sv != vpc
}
''',
     {"G": graph(), "VA": VPC, "VB": VPC2, "SB": subnet("VB", "10.1.0.0/24", "us-east-1a"),
      "E": {"Type": "AWS::NeptuneGraph::PrivateGraphEndpoint", **DEL, "Properties": {
          "GraphIdentifier": {"Ref": "G"}, "VpcId": {"Ref": "VA"}, "SubnetIds": [{"Ref": "SB"}]}}},
     {"G": graph(), "VA": VPC, "SA": subnet("VA", "10.0.0.0/24", "us-east-1a"),
      "E": {"Type": "AWS::NeptuneGraph::PrivateGraphEndpoint", **DEL, "Properties": {
          "GraphIdentifier": {"Ref": "G"}, "VpcId": {"Ref": "VA"}, "SubnetIds": [{"Ref": "SA"}]}}})

rule("pf-neptunegraph-vector-dimension-range", "neptunegraph", ["AWS::NeptuneGraph::Graph"],
     "VectorSearchDimension must be within 1-65536", U_NGAPI,
     BENCH_NONE,
     r'''# API モデル（neptune-graph 2023-11-29 VectorSearchDimension）: min 1 / max 65536。
# 同梱エンジンのスキーマはどちらの端も持たない（2026-09-22 guard: 0 と 65537 が clean）。
_pf_ngvdim_out(n) if n < 1

_pf_ngvdim_out(n) if n > 65536

violation contains make_diag_full("pf-neptunegraph-vector-dimension-range", "ERROR", name,
	"Properties.VectorSearchConfiguration.VectorSearchDimension",
	sprintf("VectorSearchDimension %v is outside 1-65536; Neptune Analytics rejects the graph at create time", [n]),
	"Use a vector dimension between 1 and 65536",
	"''' + U_NGAPI + r'''") if {
	some name in resources_of_type("AWS::NeptuneGraph::Graph")
	n := to_number(resolve(name, "Properties.VectorSearchConfiguration.VectorSearchDimension"))
	_pf_ngvdim_out(n)
}
''',
     {"G": graph(VectorSearchConfiguration={"VectorSearchDimension": 0}),
      "G2": graph(VectorSearchConfiguration={"VectorSearchDimension": 65537})},
     {"G": graph(VectorSearchConfiguration={"VectorSearchDimension": 1}),
      "G2": graph(VectorSearchConfiguration={"VectorSearchDimension": 65536})})

# 機械の境界チェックに乗らないルール（理由付き）。既存行のうち pf-neptune* は毎回書き直す。
BOUNDARY_EXCEPTIONS = {
    "pf-neptune-serverless-min-le-max":
        "MinCapacity / MaxCapacity は 0.5 NCU 刻みなので、最も近い違反値の差は 0.5 であって 1 ではない"
        "（fail は 3.0/2.5 に乗せてある）。機械チェックは整数 1 の差を要求する。pass は 2.5/2.5 で限界そのものに乗せてある",
}


def meta(r):
    types = "[" + ", ".join(r["types"]) + "]"
    return (
        f"id: {r['id']}\n"
        f"service: {r['service']}\n"
        f"resourceTypes: {types}\n"
        "severity: ERROR\n"
        f"title: {json.dumps(r['title'], ensure_ascii=False)}\n"
        f"constraintSource: {r['source']}\n"
        "upstream: none\n"
        "repro:\n"
        "  method: real-deploy\n"
        f"  evidence: {json.dumps(r['evidence'], ensure_ascii=False)}\n"
        "benchRegion: us-east-1\n"
        f"addedOn: {ADDED}\n"
    )


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def main():
    only = set(sys.argv[1:])
    for svc in ("neptune", "neptunegraph"):
        d = os.path.join(WT, "rules", svc)
        if os.path.isdir(d) and not only:
            for sub in os.listdir(d):
                if sub.startswith("pf-") and sub not in {r["id"] for r in RULES}:
                    shutil.rmtree(os.path.join(d, sub))
    write(os.path.join(WT, "rules", "_lib", "neptune.rego"), LIB)
    for r in RULES:
        if only and r["id"] not in only:
            continue
        base = os.path.join(WT, "rules", r["service"], r["id"])
        write(os.path.join(base, "rule.rego"), r["rego"])
        write(os.path.join(base, "meta.yaml"), meta(r))
        write(os.path.join(base, "templates", "fail.template.json"), json.dumps({"Resources": r["fail"]}, indent=2) + "\n")
        write(os.path.join(base, "templates", "pass.template.json"), json.dumps({"Resources": r["pass_"]}, indent=2) + "\n")
    # boundary exceptions: pf-neptune* 行を消してから、id 順の位置に差し込む
    bx = os.path.join(WT, "rules", "_boundary-exceptions.txt")
    lines = [l for l in open(bx).read().split("\n") if not l.startswith("pf-neptune")]
    while lines and lines[-1] == "":
        lines.pop()
    for rid, why in sorted(BOUNDARY_EXCEPTIONS.items()):
        idx = len(lines)
        for i, l in enumerate(lines):
            if l.startswith("pf-") and l.split()[0] > rid:
                idx = i
                break
        lines.insert(idx, f"{rid}  {why}")
    write(bx, "\n".join(lines) + "\n")
    pend = "/root/cdk-preflight-surveys/docdb-neptune-redshift-66/pending-neptune.txt"
    write(pend, "".join(r["id"] + "\n" for r in RULES))
    print(f"{len(RULES)} rules written; pending -> {pend}")


if __name__ == "__main__":
    main()
