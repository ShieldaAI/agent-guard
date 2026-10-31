"""Bounded joins to existing AWS inventory; these observations never grant access.

Only integration-owned reference nodes and outgoing links are written. The
provider graph keeps its own identity, lifecycle, timestamps and IAM semantics.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

MAX_CLOUD_REFERENCES = 1024
CLOUD_QUERY_SECONDS = 5
PROVIDER_LABELS = frozenset({"AWSRole", "AWSUser", "AWSS3Bucket"})
REFERENCE_LABELS = ("GuardExternalIdentity", "GuardExternalResource")
CLOUD_RELATIONSHIPS = ("G_CLOUD_MATCH", "G_CLOUD_CONTAINER")


class CloudJoinError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CloudScope:
    company_id: str
    tenant_id: str
    accounts: tuple[tuple[str, str], ...]
    max_age_seconds: int = 7200


def _identifier(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > 4096
        or not any(character != "\ufeff" and not character.isspace() for character in value)
        or "\0" in value
        or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        raise CloudJoinError("CLOUD_CONFIG_INVALID")
    return value


def validate_cloud_scope(value: Any) -> CloudScope:
    """Validate explicit company/tenant account enrollment; no credential discovery."""
    if isinstance(value, CloudScope):
        value = {
            "companyId": value.company_id,
            "tenantId": value.tenant_id,
            "accounts": [
                {"partition": partition, "accountId": account}
                for partition, account in value.accounts
            ],
            "maxAgeSeconds": value.max_age_seconds,
        }
    if type(value) is not dict or not {"companyId", "tenantId", "accounts"} <= value.keys():
        raise CloudJoinError("CLOUD_CONFIG_INVALID")
    if value.keys() - {"companyId", "tenantId", "accounts", "maxAgeSeconds"}:
        raise CloudJoinError("CLOUD_CONFIG_INVALID")
    company = _identifier(value["companyId"])
    tenant = _identifier(value["tenantId"])
    maximum_age = value.get("maxAgeSeconds", 7200)
    if type(maximum_age) is not int or not 1 <= maximum_age <= 604800:
        raise CloudJoinError("CLOUD_CONFIG_INVALID")
    accounts = value["accounts"]
    if type(accounts) is not list or not 1 <= len(accounts) <= 64:
        raise CloudJoinError("CLOUD_CONFIG_INVALID")
    selected = []
    for account in accounts:
        if type(account) is not dict or set(account) != {"partition", "accountId"}:
            raise CloudJoinError("CLOUD_CONFIG_INVALID")
        if account["partition"] not in ("aws", "aws-cn", "aws-us-gov") or not (
            type(account["accountId"]) is str and re.fullmatch(r"[0-9]{12}", account["accountId"])
        ):
            raise CloudJoinError("CLOUD_CONFIG_INVALID")
        entry = (account["partition"], account["accountId"])
        if entry in selected:
            raise CloudJoinError("CLOUD_CONFIG_INVALID")
        selected.append(entry)
    return CloudScope(company, tenant, tuple(sorted(selected)), maximum_age)


def check_cloud_scope(scope: CloudScope, source: dict) -> None:
    if scope.company_id != source["companyId"] or scope.tenant_id != source["tenantId"]:
        raise CloudJoinError("CLOUD_SCOPE_MISMATCH")


def provider_target(reference: dict, scope: CloudScope) -> dict | None:
    """Select a fixed pinned-provider matcher. Object/prefix links mean containment."""
    if (reference["partition"], reference["account_id"]) not in scope.accounts:
        return None
    arn = reference["arn"]
    if reference["label"] == "GuardExternalIdentity":
        prefix = f"arn:{reference['partition']}:iam::{reference['account_id']}:"
        if arn.startswith(prefix + "role/"):
            label = "AWSRole"
        elif arn.startswith(prefix + "user/"):
            label = "AWSUser"
        else:
            return None
        return {"label": label, "id": arn, "arn": arn, "relationship": "G_CLOUD_MATCH"}
    prefix = f"arn:{reference['partition']}:s3:::"
    if not arn.startswith(prefix) or reference["kind"] not in ("bucket", "object", "prefix"):
        return None
    name = arn[len(prefix) :].split("/", 1)[0]
    return {
        "label": "AWSS3Bucket",
        "id": name,
        "arn": prefix + name,
        "relationship": "G_CLOUD_MATCH" if reference["kind"] == "bucket" else "G_CLOUD_CONTAINER",
    }


def _lookup(tx, reference: dict, target: dict, scope: CloudScope) -> list[dict]:
    label = target["label"]
    if label not in PROVIDER_LABELS:
        raise CloudJoinError("CLOUD_TARGET_INVALID")
    principal = "AND p:AWSPrincipal " if label in ("AWSRole", "AWSUser") else ""
    return [
        dict(record)
        for record in tx.run(
            f"MATCH (a:AWSAccount {{id:$account}})-[r:RESOURCE]->(p:{label} {{arn:$arn}}) "
            f"WHERE p.id=$provider_id {principal}"
            "OPTIONAL MATCH (c:GuardAwsCollection {company_id:$company,tenant_id:$tenant,partition:$partition,account_id:$account}) "
            "OPTIONAL MATCH (c)-[m:G_AWS_OBSERVED]->(p) "
            "RETURN elementId(p) AS element_id,p.id AS provider_id,p.arn AS arn, "
            "p.region AS region,p.lastupdated AS node_updated, "
            "r.lastupdated AS ownership_updated,a.lastupdated AS account_updated, "
            "c IS NOT NULL AS collection_present,c.id AS collection_id,c.captured_at AS collection_updated,c.content_hash AS collection_hash,c.status AS collection_status, "
            "c.schema_version AS collection_version,m.capture_hash AS member_hash,m.captured_at AS member_updated,m.region AS member_region LIMIT 2",
            account=reference["account_id"],
            arn=target["arn"],
            provider_id=target["id"],
            company=scope.company_id,
            tenant=scope.tenant_id,
            partition=reference["partition"],
        )
    ]


def classify_provider(
    reference: dict, target: dict, matches: list[dict], scope: CloudScope, now: int
) -> dict:
    base = {"reference": reference, "target": target, "match": None}
    if not matches:
        return {**base, "status": "unresolved", "reason": "missing"}
    if len(matches) != 1:
        return {**base, "status": "unresolved", "reason": "ambiguous"}
    match = matches[0]
    managed = match.get("collection_present", match.get("collection_id") is not None)
    if managed and match.get("member_hash") is None:
        return {**base, "status": "unresolved", "reason": "missing"}
    if managed and (
        type(match.get("collection_id")) is not str
        or not re.fullmatch(r"[a-f0-9]{64}", match["collection_id"])
        or match.get("collection_version") != 1
        or match.get("collection_status") != "complete"
        or type(match.get("collection_hash")) is not str
        or not re.fullmatch(r"[a-f0-9]{64}", match["collection_hash"])
        or match["collection_hash"] != match.get("member_hash")
        or match.get("collection_updated") != match.get("member_updated")
    ):
        return {**base, "status": "unavailable", "reason": "freshness_unknown"}
    if (
        reference["region"]
        and target["label"] == "AWSS3Bucket"
        and reference["region"] != match["region"]
    ):
        return {**base, "status": "unresolved", "reason": "region_mismatch"}
    timestamps = [
        match[field] for field in ("node_updated", "ownership_updated", "account_updated")
    ]
    if managed:
        timestamps.append(match["collection_updated"])
    if any(type(value) is not int or value < 0 or value > now for value in timestamps):
        return {**base, "status": "unavailable", "reason": "freshness_unknown"}
    if any(now - value > scope.max_age_seconds for value in timestamps):
        return {**base, "status": "stale", "reason": "stale"}
    if managed and (
        match["node_updated"] != match["collection_updated"]
        or match["ownership_updated"] != match["collection_updated"]
        or (target["label"] == "AWSS3Bucket" and match.get("member_region") != match["region"])
    ):
        return {**base, "status": "unavailable", "reason": "changed"}
    return {**base, "status": "resolved", "reason": None, "match": match}


def _unavailable(reference: dict, reason: str) -> dict:
    return {
        "reference": reference,
        "target": None,
        "match": None,
        "status": "unavailable",
        "reason": reason,
    }


def collect_cloud(session, rows: dict[str, list[dict]], scope: CloudScope) -> dict:
    """Read bounded provider evidence in a separate timed transaction before staging."""
    now = int(time.time())
    references = [{**row, "label": label} for label in REFERENCE_LABELS for row in rows[label]]
    if len(references) > MAX_CLOUD_REFERENCES:
        return {
            "observed_at": now,
            "scope": scope,
            "observations": [_unavailable(ref, "limit_exceeded") for ref in references],
        }
    observations = []
    try:
        with session.begin_transaction(timeout=CLOUD_QUERY_SECONDS) as tx:
            for reference in references:
                if (reference["partition"], reference["account_id"]) not in scope.accounts:
                    observations.append(_unavailable(reference, "scope_not_enrolled"))
                    continue
                target = provider_target(reference, scope)
                if target is None:
                    observations.append(
                        {**_unavailable(reference, "unsupported"), "status": "unresolved"}
                    )
                    continue
                observations.append(
                    classify_provider(
                        reference, target, _lookup(tx, reference, target, scope), scope, now
                    )
                )
            tx.commit()
    except Exception:
        observations = [_unavailable(reference, "capture_failed") for reference in references]
    return {"observed_at": now, "scope": scope, "observations": observations}


def publish_cloud(tx, source_id: str, projection_id: str, capture: dict | None) -> None:
    """Publish exact links with the mandatory graph, never writing shared providers.

    Provider data may change independently after this transaction. Capture times
    and lastupdated receipts are retained so consumers can display that limitation.
    """
    if capture is None:
        return
    observations = []
    now = int(time.time())
    # Reject any unexpected prepublication edge instead of accepting partial or
    # foreign targets left by a faulty loader/hook. Only this function owns them.
    unexpected = tx.run(
        "MATCH (n)-[r:G_CLOUD_MATCH|G_CLOUD_CONTAINER]->() "
        "WHERE n.projection_id=$projection RETURN count(r) AS count",
        projection=projection_id,
    ).single()["count"]
    if unexpected:
        raise CloudJoinError("CLOUD_RELATIONSHIP_CONFLICT")
    for observation in capture["observations"]:
        current = observation
        if observation["status"] == "resolved":
            try:
                candidate = classify_provider(
                    observation["reference"],
                    observation["target"],
                    _lookup(tx, observation["reference"], observation["target"], capture["scope"]),
                    capture["scope"],
                    now,
                )
            except Exception:
                # The caller must roll back this transaction before retrying
                # mandatory publication with entirely unavailable cloud data.
                raise CloudJoinError("CLOUD_RECHECK_UNAVAILABLE") from None
            if candidate != observation:
                current = _unavailable(observation["reference"], "changed")
        observations.append(current)
    updates = []
    for observation in observations:
        reference, target, match = (observation[key] for key in ("reference", "target", "match"))
        properties = {
            "cloud_status": observation["status"],
            "cloud_reason": observation["reason"],
            "cloud_observed_at": capture["observed_at"],
            "cloud_assessment": "unknown",
            "cloud_provider_label": target["label"] if match else None,
            "cloud_provider_id": target["id"] if match else None,
            "cloud_match_kind": (
                "containment" if target["relationship"] == "G_CLOUD_CONTAINER" else "exact"
            )
            if match
            else None,
            "cloud_node_updated": match["node_updated"] if match else None,
            "cloud_ownership_updated": match["ownership_updated"] if match else None,
            "cloud_account_updated": match["account_updated"] if match else None,
        }
        updates.append({"id": reference["id"], "properties": properties})
        if not match:
            continue
        label, relationship = target["label"], target["relationship"]
        if label not in PROVIDER_LABELS or relationship not in CLOUD_RELATIONSHIPS:
            raise CloudJoinError("CLOUD_TARGET_INVALID")
        principal = "AND p:AWSPrincipal " if label in ("AWSRole", "AWSUser") else ""
        linked = tx.run(
            f"MATCH (n:{reference['label']} {{id:$id,source_id:$source,projection_id:$projection}}), "
            f"(a:AWSAccount {{id:$account}})-[ownership:RESOURCE]->(p:{label} {{id:$provider_id,arn:$arn}}) "
            "WHERE elementId(p)=$element_id AND p.lastupdated=$node_updated "
            "AND a.lastupdated=$account_updated AND ownership.lastupdated=$ownership_updated "
            "AND ((p.region IS NULL AND $region IS NULL) OR p.region=$region) "
            "AND (($collection IS NULL AND NOT EXISTS { MATCH (:GuardAwsCollection {company_id:$company,tenant_id:$tenant,partition:$partition,account_id:$account}) }) "
            "OR ($collection IS NOT NULL AND EXISTS { MATCH (c:GuardAwsCollection {id:$collection,content_hash:$collection_hash,captured_at:$collection_updated,status:'complete',schema_version:1}) "
            "-[m:G_AWS_OBSERVED {capture_hash:$collection_hash,captured_at:$collection_updated}]->(p) })) "
            f"{principal}"
            f"CREATE (n)-[r:{relationship} {{evidence_kind:'provider_inventory',assessment:'unknown',observed_at:$observed_at}}]->(p) "
            "RETURN count(r) AS count",
            id=reference["id"],
            source=source_id,
            projection=projection_id,
            provider_id=target["id"],
            arn=target["arn"],
            element_id=match["element_id"],
            observed_at=capture["observed_at"],
            account=reference["account_id"],
            node_updated=match["node_updated"],
            account_updated=match["account_updated"],
            ownership_updated=match["ownership_updated"],
            region=match["region"],
            company=capture["scope"].company_id,
            tenant=capture["scope"].tenant_id,
            partition=reference["partition"],
            collection=match.get("collection_id"),
            collection_hash=match.get("collection_hash"),
            collection_updated=match.get("collection_updated"),
        ).single()["count"]
        if linked != 1:
            raise CloudJoinError("CLOUD_RECHECK_UNAVAILABLE")
    updated = tx.run(
        "UNWIND $updates AS update MATCH (n {id:update.id,source_id:$source,projection_id:$projection}) "
        "WHERE n:GuardExternalIdentity OR n:GuardExternalResource SET n += update.properties RETURN count(n) AS count",
        updates=updates,
        source=source_id,
        projection=projection_id,
    ).single()["count"]
    if updated != len(updates):
        raise CloudJoinError("CLOUD_REFERENCE_CONFLICT")
    resolved = sum(observation["status"] == "resolved" for observation in observations)
    coverage = {
        "status": "complete"
        if resolved == len(observations)
        else "partial"
        if resolved
        else "unavailable",
        "observedAt": capture["observed_at"],
        "references": len(observations),
        "resolved": resolved,
        "assessment": "unknown",
        "provider": "aws",
        "maxAgeSeconds": capture["scope"].max_age_seconds,
    }
    tx.run(
        "MATCH (p:GuardSnapshot {id:$projection,source_id:$source}) SET p.cloud_coverage_json=$coverage",
        projection=projection_id,
        source=source_id,
        coverage=json.dumps(coverage, sort_keys=True, separators=(",", ":")),
    ).consume()


def unavailable_cloud(capture: dict) -> dict:
    """Discard a failed optional publication attempt before the mandatory retry."""
    return {
        **capture,
        "observations": [
            _unavailable(observation["reference"], "capture_failed")
            for observation in capture["observations"]
        ],
    }
