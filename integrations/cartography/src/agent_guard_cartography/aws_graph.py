"""Atomic bounded AWS inventory publication using pinned Cartography schemas.

Provider nodes are shared evidence. Only this integration's collection membership
and candidate policy edges are retired; shared provider/Guard data is preserved.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import make_dataclass, replace
from datetime import datetime
from hashlib import sha256

from cartography.graph.querybuilder import build_ingestion_query
from cartography.models.aws.iam.role import AWSRoleSchema
from cartography.models.aws.iam.user import AWSUserSchema
from cartography.models.aws.s3.bucket import S3BucketSchema
from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties

from agent_guard_cartography.aws_config import (
    AwsCollectionError,
    AwsEnrollment,
    collection_id,
    validate_aws_enrollment,
)
from agent_guard_cartography.aws_policy import validate_policy_evidence

_ROLE = {"arn", "roleid", "name", "path", "createdate", "createdate_dt"}
_USER = {
    "arn",
    "userid",
    "name",
    "path",
    "createdate",
    "createdate_dt",
    "passwordlastused",
    "passwordlastused_dt",
}
_BUCKET = {"Name", "Arn", "Region", "CreationDate"}
_LABELS = {"roles": "AWSRole", "users": "AWSUser", "buckets": "AWSS3Bucket"}


def _fail(code: str = "AWS_CAPTURE_INVALID") -> None:
    raise AwsCollectionError(code)


def _text(value, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        _fail()
    return value


def _date(value) -> datetime:
    _text(value, 128)
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
            _fail()
        return result
    except (ValueError, OverflowError):
        _fail()


def validate_aws_capture(enrollment: AwsEnrollment, value: object) -> dict:
    """Copy the small allowlisted wire shape before opening any graph transaction."""
    enrollment = validate_aws_enrollment(enrollment)
    expected_fields = {"capturedAt", "roles", "users", "buckets"}
    if enrollment.include_iam_policy_evidence:
        expected_fields.add("policyEvidence")
    if type(value) is not dict or set(value) != expected_fields:
        _fail()
    stamp = value["capturedAt"]
    if type(stamp) is not int or not 0 <= stamp <= int(time.time()):
        _fail()
    if any(type(value[name]) is not list for name in _LABELS):
        _fail()
    if sum(len(value[name]) for name in _LABELS) > enrollment.max_items:
        _fail("AWS_CAPTURE_LIMIT_EXCEEDED")
    result = {"capturedAt": stamp, "roles": [], "users": [], "buckets": []}
    size = 128
    for category, fields in (("roles", _ROLE), ("users", _USER), ("buckets", _BUCKET)):
        seen = set()
        for row in value[category]:
            if type(row) is not dict or set(row) != fields:
                _fail()
            copied = dict(row)
            if category == "buckets":
                name = _text(row["Name"], 63)
                if (
                    not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", name)
                    or ".." in name
                    or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", name)
                ):
                    _fail()
                if row["Arn"] != f"arn:{enrollment.partition}:s3:::{name}":
                    _fail()
                if not re.fullmatch(
                    r"[a-z]{2}-(?:[a-z]+-)+[0-9]+", _text(row["Region"], 32)
                ) or row["Region"].startswith(("cn-", "us-gov-")):
                    _fail()
                _date(row["CreationDate"])
                identity = name
            else:
                kind, id_key = ("role", "roleid") if category == "roles" else ("user", "userid")
                name = _text(row["name"], 128)
                path = _text(row["path"], 512)
                if (
                    not re.fullmatch(r"[A-Za-z0-9+=,.@_-]+", name)
                    or not path.startswith("/")
                    or not path.endswith("/")
                ):
                    _fail()
                if (
                    row["arn"]
                    != f"arn:{enrollment.partition}:iam::{enrollment.account_id}:{kind}{path}{name}"
                ):
                    _fail()
                _text(row[id_key], 128)
                _text(row["createdate"], 128)
                _date(row["createdate_dt"])
                if category == "users" and (
                    row["passwordlastused"] != "" or row["passwordlastused_dt"] is not None
                ):
                    _fail()
                identity = row["arn"]
            if identity in seen:
                _fail()
            seen.add(identity)
            size += len(json.dumps(copied, ensure_ascii=True, separators=(",", ":")).encode()) + 1
            if size > enrollment.max_capture_bytes:
                _fail("AWS_CAPTURE_LIMIT_EXCEEDED")
            result[category].append(copied)
        result[category].sort(
            key=lambda item: item["Name"] if category == "buckets" else item["arn"]
        )
    if enrollment.include_iam_policy_evidence:
        result["policyEvidence"] = validate_policy_evidence(
            enrollment, result, value["policyEvidence"]
        )
    if (
        len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode())
        > enrollment.max_capture_bytes
    ):
        _fail("AWS_CAPTURE_LIMIT_EXCEEDED")
    return result


def _schemas():
    # ListUsers does not authorize collecting password-use observations. Preserve
    # any independently collected properties while reusing every canonical ref,
    # label, ownership edge and ontology mapping for the metadata we do observe.
    user = AWSUserSchema()
    properties = user.properties
    names = ("id", "lastupdated", "arn", "userid", "name", "path", "createdate", "createdate_dt")
    metadata = make_dataclass(
        "AwsUserMetadataProperties",
        [(name, PropertyRef, getattr(properties, name)) for name in names],
        bases=(CartographyNodeProperties,),
        frozen=True,
    )
    return {
        "roles": AWSRoleSchema(),
        "users": replace(user, properties=metadata()),
        "buckets": S3BucketSchema(),
    }


def _publish_policy_evidence(tx, identifier: str, capture: dict, content_hash: str) -> None:
    """Replace only this collection's candidate layer inside the metadata transaction."""
    tx.run(
        "MATCH ()-[r:G_AWS_POLICY_CANDIDATE {collection_id:$id}]->() DELETE r",
        id=identifier,
    ).consume()
    evidence = capture.get("policyEvidence")
    if evidence is None:
        tx.run(
            "MATCH (c:GuardAwsCollection {id:$id}) SET c.policy_status='disabled' "
            "REMOVE c.policy_hash,c.policy_mapping_version,c.policy_principals,c.policy_edges,"
            "c.policy_groups,c.policy_managed_policies,c.policy_inline_policies,c.policy_statements",
            id=identifier,
        ).consume()
        return
    parameters = {
        "id": identifier,
        "hash": content_hash,
        "stamp": capture["capturedAt"],
        "policy_hash": evidence["policyHash"],
        "mapping_version": evidence["mappingVersion"],
    }
    count = tx.run(
        "MATCH (c:GuardAwsCollection {id:$id}) UNWIND $rows AS row "
        "MATCH (c)-[m:G_AWS_OBSERVED]->(p:AWSPrincipal {id:row.arn}) "
        "WHERE m.capture_hash=$hash AND m.captured_at=$stamp "
        "SET m.policy_status=row.status,m.policy_boundary_present=row.boundaryPresent,"
        "m.policy_hash=$policy_hash,m.policy_mapping_version=$mapping_version,"
        "m.policy_assessment='unknown' RETURN count(m) AS count",
        **parameters,
        rows=evidence["principals"],
    ).single()["count"]
    if count != len(evidence["principals"]):
        _fail("AWS_PROVIDER_CONFLICT")
    count = tx.run(
        "MATCH (c:GuardAwsCollection {id:$id}) UNWIND $rows AS row "
        "MATCH (c)-[pm:G_AWS_OBSERVED]->(p:AWSPrincipal {id:row.principalArn}) "
        "MATCH (c)-[bm:G_AWS_OBSERVED]->(b:AWSS3Bucket {arn:row.bucketArn}) "
        "WHERE pm.capture_hash=$hash AND bm.capture_hash=$hash "
        "AND pm.captured_at=$stamp AND bm.captured_at=$stamp AND pm.policy_status='mapped' "
        "CREATE (p)-[r:G_AWS_POLICY_CANDIDATE {collection_id:$id,capture_hash:$hash,"
        "captured_at:$stamp,policy_hash:$policy_hash,mapping_version:$mapping_version,"
        "relationship:row.relationship,has_condition:row.hasCondition,condition_keys:row.conditionKeys,"
        "resource_scope:'bucket_summary',assessment:'unknown',evidence_kind:'iam_identity_policy_candidate'}]->(b) "
        "RETURN count(r) AS count",
        **parameters,
        rows=evidence["edges"],
    ).single()["count"]
    if count != len(evidence["edges"]):
        _fail("AWS_PROVIDER_CONFLICT")
    tx.run(
        "MATCH (c:GuardAwsCollection {id:$id}) SET c.policy_status='complete',"
        "c.policy_hash=$policy_hash,c.policy_mapping_version=$mapping_version,"
        "c.policy_principals=$principals,c.policy_edges=$edges,c.policy_groups=$groups,"
        "c.policy_managed_policies=$managed,c.policy_inline_policies=$inline,"
        "c.policy_statements=$statements",
        id=identifier,
        policy_hash=evidence["policyHash"],
        mapping_version=evidence["mappingVersion"],
        principals=len(evidence["principals"]),
        edges=len(evidence["edges"]),
        groups=evidence["counts"]["groups"],
        managed=evidence["counts"]["managedPolicies"],
        inline=evidence["counts"]["inlinePolicies"],
        statements=evidence["counts"]["statements"],
    ).consume()


def publish_aws_capture(session, enrollment: AwsEnrollment, capture: object) -> dict:
    """Caller holds the shared ingestion lock. A failed transaction publishes nothing."""
    enrollment = validate_aws_enrollment(enrollment)
    capture = validate_aws_capture(enrollment, capture)
    identifier = collection_id(enrollment)
    content_hash = sha256(
        json.dumps(capture, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    identity_hash = sha256(
        json.dumps(
            [enrollment.region, enrollment.expected_caller_arn], separators=(",", ":")
        ).encode()
    ).hexdigest()
    stamp = capture["capturedAt"]
    receipt = {
        "status": "complete",
        "collectionId": identifier,
        "capturedAt": stamp,
        "roles": len(capture["roles"]),
        "users": len(capture["users"]),
        "buckets": len(capture["buckets"]),
        "assessment": "unknown",
    }
    if "policyEvidence" in capture:
        evidence = capture["policyEvidence"]
        receipt["policyEvidence"] = {
            "status": "complete",
            "principals": len(evidence["principals"]),
            "edges": len(evidence["edges"]),
            "boundaryPrincipals": sum(p["boundaryPresent"] for p in evidence["principals"]),
            "unsupportedPrincipals": sum(
                p["status"] == "unsupported" for p in evidence["principals"]
            ),
        }
    try:
        with session.begin_transaction(timeout=min(30, enrollment.timeout_seconds)) as tx:
            prior = list(
                tx.run(
                    "MERGE (c:GuardAwsCollection {id:$id}) "
                    "ON CREATE SET c.schema_version=1,c.company_id=$company,c.tenant_id=$tenant,c.partition=$partition,c.account_id=$account,c.identity_hash=$identity "
                    "SET c._publication_lock=coalesce(c._publication_lock,0)+1 RETURN properties(c) AS value LIMIT 2",
                    id=identifier,
                    company=enrollment.company_id,
                    tenant=enrollment.tenant_id,
                    partition=enrollment.partition,
                    account=enrollment.account_id,
                    identity=identity_hash,
                )
            )
            if len(prior) != 1:
                _fail("AWS_PUBLICATION_CONFLICT")
            old = dict(prior[0]["value"])
            expected = {
                "schema_version": 1,
                "company_id": enrollment.company_id,
                "tenant_id": enrollment.tenant_id,
                "partition": enrollment.partition,
                "account_id": enrollment.account_id,
                "identity_hash": identity_hash,
            }
            if any(old.get(name) != expected_value for name, expected_value in expected.items()):
                _fail("AWS_ENROLLMENT_CONFLICT")
            if "captured_at" in old:
                if type(old["captured_at"]) is not int or old["captured_at"] > stamp:
                    _fail("AWS_CAPTURE_ROLLBACK")
                if old["captured_at"] == stamp:
                    if old.get("content_hash") != content_hash:
                        _fail("AWS_CAPTURE_CONFLICT")
                    tx.rollback()
                    return {**receipt, "idempotent": True}
            account_count = tx.run(
                "MATCH (a:AWSAccount {id:$account}) RETURN count(a) AS count",
                account=enrollment.account_id,
            ).single()["count"]
            if account_count > 1:
                _fail("AWS_PROVIDER_CONFLICT")
            # Reusing a bucket now owned by another account requires deliberate
            # reconciliation; never silently overwrite its old ownership evidence.
            for category, label in _LABELS.items():
                ids = [
                    row["Name"] if category == "buckets" else row["arn"]
                    for row in capture[category]
                ]
                matches = list(
                    tx.run(
                        f"UNWIND $ids AS id OPTIONAL MATCH (p:{label} {{id:id}}) "
                        "OPTIONAL MATCH (a:AWSAccount)-[r:RESOURCE]->(p) "
                        "WITH id,collect(DISTINCT p) AS nodes,collect(DISTINCT a.id) AS accounts,count(r) AS ownerships "
                        "WHERE size(nodes)>1 OR ownerships>1 OR any(account IN accounts WHERE account<>$account) "
                        "OR any(node IN nodes WHERE node.arn IS NOT NULL AND node.arn<>$prefix+id) "
                        "RETURN id LIMIT 1",
                        ids=ids,
                        account=enrollment.account_id,
                        prefix=f"arn:{enrollment.partition}:s3:::" if category == "buckets" else "",
                    )
                )
                if matches:
                    _fail("AWS_PROVIDER_CONFLICT")
            tx.run(
                "MERGE (a:AWSAccount {id:$account}) ON CREATE SET a.firstseen=timestamp() SET a.lastupdated=$stamp",
                account=enrollment.account_id,
                stamp=stamp,
            ).consume()
            for category, schema in _schemas().items():
                rows = [dict(row) for row in capture[category]]
                for row in rows:
                    if category == "buckets":
                        row["CreationDate"] = _date(row["CreationDate"])
                    else:
                        row["createdate_dt"] = _date(row["createdate_dt"])
                # The upstream load() starts its own transactions and automatic
                # indexes. Reuse its exact schema/query builder in this transaction.
                tx.run(
                    build_ingestion_query(schema),
                    DictList=rows,
                    lastupdated=stamp,
                    AWS_ID=enrollment.account_id,
                ).consume()
            tx.run(
                "MATCH (c:GuardAwsCollection {id:$id})-[r:G_AWS_OBSERVED]->() DELETE r",
                id=identifier,
            ).consume()
            for category, label in _LABELS.items():
                ids = [
                    row["Name"] if category == "buckets" else row["arn"]
                    for row in capture[category]
                ]
                linked = tx.run(
                    f"MATCH (c:GuardAwsCollection {{id:$id}}) UNWIND $ids AS target MATCH (p:{label} {{id:target}}) "
                    "CREATE (c)-[r:G_AWS_OBSERVED {capture_hash:$hash,captured_at:$stamp}]->(p) SET r.region=p.region RETURN count(r) AS count",
                    id=identifier,
                    ids=ids,
                    hash=content_hash,
                    stamp=stamp,
                ).single()["count"]
                if linked != len(ids):
                    _fail("AWS_PROVIDER_CONFLICT")
            _publish_policy_evidence(tx, identifier, capture, content_hash)
            tx.run(
                "MATCH (c:GuardAwsCollection {id:$id}) SET c.captured_at=$stamp,c.content_hash=$hash,c.status='complete'",
                id=identifier,
                stamp=stamp,
                hash=content_hash,
            ).consume()
            tx.commit()
        return {**receipt, "idempotent": False}
    except AwsCollectionError:
        raise
    except Exception:
        raise AwsCollectionError("AWS_PUBLICATION_FAILED") from None
