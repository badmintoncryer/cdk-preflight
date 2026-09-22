#!/usr/bin/env python3
"""Generator for the DocumentDB Elastic rule slice (#66 phase C2).

Writes rules/docdbelastic/<rule-id>/{rule.rego,meta.yaml,templates/fail.template.json,templates/pass.template.json}
into the worktree. Fixes go here, then re-run.
"""
import json
import os
import shutil

ROOT = "/home/user/wt-docdbelastic/rules/docdbelastic"
TYPE = "AWS::DocDBElastic::Cluster"
CFN = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdbelastic-cluster.html"
LIMITS = "https://docs.aws.amazon.com/documentdb/latest/developerguide/limits.html"
PROBE = "api-probe 2026-09-15 us-east-1: CreateCluster"
PENDING = "; bench: PENDING"
ADDED = "2026-09-22"

HEADER = "package cdk_preflight\n\nimport rego.v1\n\n"

# A literal string a user wrote (resolve() turns Ref/GetAtt into a logical id, and
# {{resolve:secretsmanager:...}} / Fn::Join over tokens stay undefined, so both skip).
LIT = "\tis_string({v})\n\tnot input.resources[{v}]\n"

BASE = {
    "AdminUserName": "pfadmin",
    "AdminUserPassword": "pfpassword1234",
    "AuthType": "PLAIN_TEXT",
    "ShardCapacity": 2,
    "ShardCount": 1,
}


def cluster(name, **over):
    p = dict(BASE)
    p["ClusterName"] = name
    p.update(over)
    return {"Type": TYPE, "Properties": p}


def template(resources, chain=False):
    """resources: list of (logical id, resource). chain=True adds DependsOn so a fail
    stack only ever attempts the first cluster (the rest never get created)."""
    out = {}
    prev = None
    for lid, res in resources:
        r = dict(res)
        if chain and prev is not None:
            r["DependsOn"] = prev
        out[lid] = r
        prev = lid
    return {"Resources": out}


def violation(rid, path, msg_fmt, args, fix, url, body):
    a = f", [{args}]" if args else ""
    msg = f'sprintf("{msg_fmt}"{a})' if args else f'"{msg_fmt}"'
    return (
        f'violation contains make_diag_full("{rid}", "ERROR", name,\n'
        f'\t"{path}",\n'
        f"\t{msg},\n"
        f"\t{fix}, {url}) if {{\n"
        f'\tsome name in resources_of_type("{TYPE}")\n'
        f"{body}}}\n"
    )


RULES = []

# ---------------------------------------------------------------- password length
rid = "pf-docdbelastic-admin-password-length"
rego = HEADER
rego += f'_pf_dbepwl_url := "{CFN}#cfn-docdbelastic-cluster-adminuserpassword"\n\n'
rego += '_pf_dbepwl_fix := "Give AdminUserPassword 8-100 characters, or set AuthType SECRET_ARN and pass a Secrets Manager secret ARN"\n\n'
body = '\tpw := resolve(name, "Properties.AdminUserPassword")\n' + LIT.format(v="pw")
rego += violation(rid, "Properties.AdminUserPassword",
                  'AdminUserPassword is %d characters; CreateCluster fails with \\"Invalid password set in the AdminUserPassword. Password must be longer than 8 ASCII characters.\\"',
                  "count(pw)", "_pf_dbepwl_fix", "_pf_dbepwl_url", body + "\tcount(pw) < 8\n")
rego += "\n"
rego += violation(rid, "Properties.AdminUserPassword",
                  'AdminUserPassword is %d characters; CreateCluster accepts 8-100 (\\"Invalid password set in the AdminUserPassword.\\")',
                  "count(pw)", "_pf_dbepwl_fix", "_pf_dbepwl_url", body + "\tcount(pw) > 100\n")
RULES.append(dict(
    id=rid, rego=rego,
    title="AdminUserPassword must be 8-100 characters",
    source=CFN + "#cfn-docdbelastic-cluster-adminuserpassword",
    evidence=PROBE + ' with a 7 character AdminUserPassword -> "ValidationException: Invalid password set in the AdminUserPassword. Password must be longer than 8 ASCII characters." (#66 phase B; the 101 character end is unprobed)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-pwlen-fail-a", AdminUserPassword="x" * 7)),
                   ("C2", cluster("cdkpf-dbe-pwlen-fail-b", AdminUserPassword="x" * 101))], chain=True),
    pass_=template([("C", cluster("cdkpf-dbe-pwlen-pass-a", AdminUserPassword="x" * 8)),
                    ("C2", cluster("cdkpf-dbe-pwlen-pass-b", AdminUserPassword="x" * 100))]),
))

# ---------------------------------------------------------------- password charset
rid = "pf-docdbelastic-admin-password-charset"
rego = HEADER
rego += f'_pf_dbepwc_url := "{CFN}#cfn-docdbelastic-cluster-adminuserpassword"\n\n'
rego += '_pf_dbepwc_fix := "Remove the forward slash, double quote or at sign from AdminUserPassword, or set AuthType SECRET_ARN and pass a Secrets Manager secret ARN"\n\n'
rego += '_pf_dbepwc_forbidden := {"/", "\\"", "@"}\n\n'
body = '\tpw := resolve(name, "Properties.AdminUserPassword")\n' + LIT.format(v="pw")
body += "\tsome ch in _pf_dbepwc_forbidden\n\tcontains(pw, ch)\n"
rego += violation(rid, "Properties.AdminUserPassword",
                  "AdminUserPassword contains '%s'; a forward slash, double quote or at sign is not allowed and CreateCluster fails with \\\"Invalid password set in the AdminUserPassword.\\\"",
                  "ch", "_pf_dbepwc_fix", "_pf_dbepwc_url", body)
RULES.append(dict(
    id=rid, rego=rego,
    title="AdminUserPassword must not contain a forward slash, double quote or at sign",
    source=CFN + "#cfn-docdbelastic-cluster-adminuserpassword",
    evidence=PROBE + ' with a forbidden character in AdminUserPassword -> "ValidationException: Invalid password set in the AdminUserPassword." (#66 phase B, UNNAMED: the message does not name the character; a length violation gets a different sentence)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-pwchar-fail", AdminUserPassword="pf@password1234"))]),
    pass_=template([("C", cluster("cdkpf-dbe-pwchar-pass", AdminUserPassword="pf#password!1234"))]),
))

# ---------------------------------------------------------------- username first char
rid = "pf-docdbelastic-admin-username-first-char"
rego = HEADER
rego += f'_pf_dbeun_url := "{CFN}#cfn-docdbelastic-cluster-adminusername"\n\n'
rego += '_pf_dbeun_fix := "Start AdminUserName with a letter (1-63 letters or numbers)"\n\n'
body = '\tu := resolve(name, "Properties.AdminUserName")\n' + LIT.format(v="u")
body += "\tnot regex.match(`^[A-Za-z]`, u)\n"
rego += violation(rid, "Properties.AdminUserName",
                  "AdminUserName '%s' does not start with a letter; CreateCluster fails with \\\"Invalid admin user name - %s.\\\"",
                  "u, u", "_pf_dbeun_fix", "_pf_dbeun_url", body)
RULES.append(dict(
    id=rid, rego=rego,
    title="AdminUserName must start with a letter",
    source=CFN + "#cfn-docdbelastic-cluster-adminusername",
    evidence=PROBE + ' with AdminUserName 1pfadmin -> "ValidationException: Invalid admin user name - 1pfadmin." (#66 phase B, UNNAMED: the message names the property, not the rule)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-uname-fail", AdminUserName="1pfadmin"))]),
    pass_=template([("C", cluster("cdkpf-dbe-uname-pass", AdminUserName="pfadmin1"))]),
))

# ---------------------------------------------------------------- maintenance window >= 30 min
rid = "pf-docdbelastic-maintenance-window-duration"
rego = HEADER
rego += f'_pf_dbemw_url := "{CFN}#cfn-docdbelastic-cluster-preferredmaintenancewindow"\n\n'
rego += '_pf_dbemw_fix := "Give PreferredMaintenanceWindow (ddd:hh24:mi-ddd:hh24:mi, UTC) at least 30 minutes, e.g. sun:23:00-sun:23:30"\n\n'
rego += '''# to_number("03") is undefined in the engine's Rego build, so digits go through a table.
_pf_dbemw_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_dbemw_days := {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

# "hh:mi" -> minutes of day; undefined for anything else.
_pf_dbemw_min(t) := m if {
\tregex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
\th := (_pf_dbemw_digit[substring(t, 0, 1)] * 10) + _pf_dbemw_digit[substring(t, 1, 1)]
\tmi := (_pf_dbemw_digit[substring(t, 3, 1)] * 10) + _pf_dbemw_digit[substring(t, 4, 1)]
\tm := (h * 60) + mi
}

# "ddd:hh24:mi-ddd:hh24:mi" -> length in minutes, wrapping around the week.
# A window that does not parse is left alone (the format itself is not this rule's constraint).
_pf_dbemw_minutes(w) := n if {
\tparts := split(lower(w), "-")
\tcount(parts) == 2
\tp1 := split(parts[0], ":")
\tp2 := split(parts[1], ":")
\tcount(p1) == 3
\tcount(p2) == 3
\tstart := (_pf_dbemw_days[p1[0]] * 1440) + _pf_dbemw_min(sprintf("%s:%s", [p1[1], p1[2]]))
\tend := (_pf_dbemw_days[p2[0]] * 1440) + _pf_dbemw_min(sprintf("%s:%s", [p2[1], p2[2]]))
\tn := ((end - start) + 10080) % 10080
}

'''
body = '\tw := resolve(name, "Properties.PreferredMaintenanceWindow")\n' + LIT.format(v="w")
body += "\tn := _pf_dbemw_minutes(w)\n\tn < 30\n"
rego += violation(rid, "Properties.PreferredMaintenanceWindow",
                  "the maintenance window '%s' is %d minutes long; CreateCluster fails with \\\"Maintenance window must be at least 30 minutes long.\\\"",
                  "w, n", "_pf_dbemw_fix", "_pf_dbemw_url", body)
RULES.append(dict(
    id=rid, rego=rego,
    title="PreferredMaintenanceWindow must span at least 30 minutes",
    source=CFN + "#cfn-docdbelastic-cluster-preferredmaintenancewindow",
    evidence=PROBE + ' with a 29 minute PreferredMaintenanceWindow -> "ValidationException: Maintenance window must be at least 30 minutes long." (#66 phase B)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-mw-fail", PreferredMaintenanceWindow="sun:23:00-sun:23:29"))]),
    pass_=template([("C", cluster("cdkpf-dbe-mw-pass", PreferredMaintenanceWindow="sun:23:00-sun:23:30"))]),
))

# ---------------------------------------------------------------- shard capacity enum (+ max merged)
rid = "pf-docdbelastic-shard-capacity-enum"
rego = HEADER
rego += f'_pf_dbesc_url := "{CFN}#cfn-docdbelastic-cluster-shardcapacity"\n\n'
rego += '_pf_dbesc_fix := "Set ShardCapacity to one of 2, 4, 8, 16, 32 or 64 vCPUs"\n\n'
rego += "_pf_dbesc_allowed := {2, 4, 8, 16, 32, 64}\n\n"
body = '\tv := to_number(resolve(name, "Properties.ShardCapacity"))\n\tnot v in _pf_dbesc_allowed\n'
rego += violation(rid, "Properties.ShardCapacity",
                  "ShardCapacity is %v; CreateCluster fails with \\\"Invalid Input - '%v'. ShardCapacity must be a power of 2 within [2, 64].\\\"",
                  "v, v", "_pf_dbesc_fix", "_pf_dbesc_url", body)
RULES.append(dict(
    id=rid, rego=rego,
    title="ShardCapacity must be one of 2, 4, 8, 16, 32 or 64 vCPUs",
    source=CFN + "#cfn-docdbelastic-cluster-shardcapacity",
    evidence=PROBE + ' ShardCapacity 3 -> "ValidationException: Invalid Input - \'3\'. ShardCapacity must be a power of 2 within [2, 64]."; ShardCapacity 128 -> same sentence with \'128\' (#66 phase B; pf-dbe-shard-capacity-max merged here, the chained second fail cluster carries 128; pass stays at 2 vCPU because 64 vCPU is $8.45/hr)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-cap-fail-a", ShardCapacity=3)),
                   ("C2", cluster("cdkpf-dbe-cap-fail-b", ShardCapacity=128))], chain=True),
    pass_=template([("C", cluster("cdkpf-dbe-cap-pass", ShardCapacity=2))]),
))

# ---------------------------------------------------------------- shard count <= 32
rid = "pf-docdbelastic-shard-count-max"
rego = HEADER
rego += f'_pf_dbecnt_url := "{LIMITS}"\n\n'
rego += '_pf_dbecnt_fix := "Use at most 32 shards (a hard quota, not adjustable); scale ShardCapacity instead"\n\n'
body = '\tv := to_number(resolve(name, "Properties.ShardCount"))\n\tv > 32\n'
rego += violation(rid, "Properties.ShardCount",
                  "ShardCount is %v; CreateCluster fails with \\\"Invalid Input - '%v'. ShardCount should be between 1 and 32.\\\"",
                  "v, v", "_pf_dbecnt_fix", "_pf_dbecnt_url", body)
RULES.append(dict(
    id=rid, rego=rego,
    title="ShardCount must not exceed 32",
    source=LIMITS,
    evidence=PROBE + ' ShardCount 33 -> "ValidationException: Invalid Input - \'33\'. ShardCount should be between 1 and 32." (#66 phase B; the pass fixture is 32 shards x 2 vCPU = $8.45/hr, run the bench --fail-only)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-cnt-fail", ShardCount=33))]),
    pass_=template([("C", cluster("cdkpf-dbe-cnt-pass", ShardCount=32))]),
))

# ---------------------------------------------------------------- shard instance count <= 16
rid = "pf-docdbelastic-shard-instance-count-max"
rego = HEADER
rego += f'_pf_dbesic_url := "{LIMITS}"\n\n'
rego += '_pf_dbesic_fix := "Use at most 16 instances per shard (1 writer + up to 15 replicas)"\n\n'
body = '\tv := to_number(resolve(name, "Properties.ShardInstanceCount"))\n\tv > 16\n'
rego += violation(rid, "Properties.ShardInstanceCount",
                  "ShardInstanceCount is %v; CreateCluster fails with \\\"Invalid Input - '%v'. ShardInstanceCount should be between 1 and 16.\\\"",
                  "v, v", "_pf_dbesic_fix", "_pf_dbesic_url", body)
RULES.append(dict(
    id=rid, rego=rego,
    title="ShardInstanceCount must not exceed 16",
    source=LIMITS,
    evidence=PROBE + ' ShardInstanceCount 17 -> "ValidationException: Invalid Input - \'17\'. ShardInstanceCount should be between 1 and 16." (#66 phase B; the pass fixture is 16 instances x 2 vCPU = $4.22/hr, run the bench --fail-only)' + PENDING,
    fail=template([("C", cluster("cdkpf-dbe-sic-fail", ShardInstanceCount=17))]),
    pass_=template([("C", cluster("cdkpf-dbe-sic-pass", ShardInstanceCount=16))]),
))


def yq(s):
    return json.dumps(s)  # YAML double-quoted scalar == JSON string


def write(rule):
    d = os.path.join(ROOT, rule["id"])
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "templates"))
    with open(os.path.join(d, "rule.rego"), "w") as f:
        f.write(rule["rego"])
    meta = (
        f"id: {rule['id']}\n"
        f"service: docdbelastic\n"
        f"resourceTypes: [{TYPE}]\n"
        f"severity: ERROR\n"
        f"title: {yq(rule['title'])}\n"
        f"constraintSource: {rule['source']}\n"
        f"upstream: none\n"
        f"repro:\n"
        f"  method: real-deploy\n"
        f"  evidence: {yq(rule['evidence'])}\n"
        f"addedOn: {ADDED}\n"
    )
    with open(os.path.join(d, "meta.yaml"), "w") as f:
        f.write(meta)
    for kind, tpl in (("fail", rule["fail"]), ("pass", rule["pass_"])):
        with open(os.path.join(d, "templates", f"{kind}.template.json"), "w") as f:
            json.dump(tpl, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    for r in RULES:
        write(r)
    print("wrote", len(RULES), "rules:", " ".join(r["id"] for r in RULES))
