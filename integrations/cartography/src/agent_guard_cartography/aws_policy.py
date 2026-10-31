"""Bounded IAM identity-policy candidates, never an effective authorization result.

Provider documents live only inside the capture worker. Publication receives a
strict, independently validated reduction with no policy or condition values.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import unquote

from cartography.intel.aws.permission_relationships import calculate_permission_relationships

from agent_guard_cartography.aws_config import AwsCollectionError

FILTER = ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
MAPPING_VERSION = "s3-identity-policy-v1"
MAPPINGS = (
    ("CAN_READ", "s3:GetObject"),
    ("CAN_WRITE", "s3:PutObject"),
    ("CAN_LIST", "s3:ListBucket"),
)
_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]+")
_HASH = re.compile(r"[a-f0-9]{64}")


def _fail(code="AWS_POLICY_INVALID"):
    raise AwsCollectionError(code)


def _text(value, maximum=2048):
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8", "surrogatepass")) > maximum
        or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        _fail()
    return value


def _date(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_date,
        ).encode()
    except (ValueError, TypeError, RecursionError, OverflowError):
        _fail()


def _list(value, key):
    result = value.get(key, [])
    if type(result) is not list:
        _fail()
    return result


def _unique(values):
    if len(values) != len(set(values)):
        _fail("AWS_POLICY_INCOMPLETE")


def _policy_arn(enrollment, value):
    value = _text(value)
    if not re.fullmatch(
        rf"arn:aws:iam::(?:{enrollment.account_id}|aws):policy/[A-Za-z0-9_+=,.@/-]+", value
    ):
        _fail("AWS_POLICY_INCOMPLETE")
    return value


def _document(value):
    # Botocore normally decodes documents to dictionaries. Also accept its wire
    # string representation for offline consumers, with duplicate-key rejection.
    if len(_json(value)) > 131_072:
        _fail("AWS_POLICY_LIMIT_EXCEEDED")
    if type(value) is str:

        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    _fail()
                result[key] = item
            return result

        try:
            wire = (
                unquote(value, errors="strict")
                if value.lstrip().lower().startswith("%7b")
                else value
            )
            value = json.loads(wire, object_pairs_hook=pairs)
        except (ValueError, UnicodeError, RecursionError):
            _fail()
    if type(value) is not dict or "Statement" not in value:
        _fail()
    pending = [(value, 0)]
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if nodes > 20_000 or depth > 16:
            _fail("AWS_POLICY_LIMIT_EXCEEDED")
        if type(node) is dict:
            pending.extend((item, depth + 1) for item in node.values())
        elif type(node) is list:
            pending.extend((item, depth + 1) for item in node)
    statements = value["Statement"]
    if type(statements) is dict:
        statements = [statements]
    if type(statements) is not list:
        _fail()
    unsupported = bool(value.keys() - {"Version", "Id", "Statement"})
    if value.get("Version", "2012-10-17") not in ("2012-10-17", "2008-10-17"):
        unsupported = True
    normalized = []
    work = 0
    for statement in statements:
        if type(statement) is not dict or statement.get("Effect") not in ("Allow", "Deny"):
            _fail()
        unsupported |= bool(
            statement.keys()
            - {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
        )
        unsupported |= "NotAction" in statement or "NotResource" in statement
        unsupported |= ("Action" in statement) == ("NotAction" in statement)
        unsupported |= ("Resource" in statement) == ("NotResource" in statement)
        entry = {"effect": statement["Effect"]}
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key not in statement:
                continue
            values = statement[key]
            if type(values) is str:
                values = [values]
            if type(values) is not list or not values:
                _fail()
            compiled = []
            for selector in values:
                selector = _text(selector, 2048)
                # One wildcard per selector bounds regex backtracking. Advanced
                # expressions suppress the entire principal, including its allows.
                unsupported |= "${" in selector or selector.count("*") > 1
                if key.endswith("Action"):
                    unsupported |= not bool(re.fullmatch(r"[A-Za-z0-9*?:_-]+", selector))
                pattern = re.escape(selector).replace(r"\*", ".*").replace(r"\?", ".")
                if not key.endswith("Action"):
                    # Cartography's S3 object-to-bucket fallback recompiles the
                    # pre-slash regex with IGNORECASE. Keep resource case in a
                    # scoped group that survives that split; action case stays
                    # insensitive, and object-key scope remains bucket_summary.
                    bucket, slash, suffix = pattern.partition("/")
                    pattern = f"(?-i:{bucket}){slash}{suffix}"
                compiled.append(re.compile(pattern, re.IGNORECASE if key.endswith("Action") else 0))
            work += len(values)
            entry[key.lower()] = compiled
        if "Condition" in statement:
            conditions = statement["Condition"]
            if type(conditions) is not dict or not conditions:
                _fail()
            if len(conditions) > 32:
                _fail("AWS_POLICY_LIMIT_EXCEEDED")
            safe = {}
            keys = set()
            for operator, context in conditions.items():
                _text(operator, 128)
                if type(context) is not dict or not context:
                    _fail()
                safe[operator] = {}
                for key, raw in context.items():
                    keys.add(_text(key, 256))
                    values = raw if type(raw) is list else [raw]
                    if not values or any(
                        type(item) not in (str, int, float, bool) for item in values
                    ):
                        _fail()
                    if len(values) > 128 or any(
                        type(item) is str and len(item) > 8192 for item in values
                    ):
                        _fail("AWS_POLICY_LIMIT_EXCEEDED")
                    safe[operator][key] = "present"
            if len(keys) > 128:
                _fail("AWS_POLICY_LIMIT_EXCEEDED")
            entry["condition"] = [safe]
        normalized.append(entry)
    return normalized, unsupported, max(work, len(normalized)), sha256(_json(value)).hexdigest()


def capture_policy_evidence(enrollment, metadata_capture, call, page):
    """Read one complete authorization census using one explicitly allowed API."""
    if not enrollment.include_iam_policy_evidence:
        _fail()
    census = {
        key: [] for key in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
    }
    marker = None
    markers = set()
    raw_size = 0
    items = 0
    while True:
        page()
        response = call(
            "iam",
            "get_account_authorization_details",
            Filter=list(FILTER),
            MaxItems=100,
            **({"Marker": marker} if marker else {}),
        )
        if type(response) is not dict or type(response.get("IsTruncated")) is not bool:
            _fail()
        raw_size += len(_json(response))
        if raw_size > enrollment.max_policy_bytes:
            _fail("AWS_POLICY_LIMIT_EXCEEDED")
        for key in census:
            entries = _list(response, key)
            if any(type(entry) is not dict for entry in entries):
                _fail()
            items += len(entries)
            if items > enrollment.max_items:
                _fail("AWS_POLICY_LIMIT_EXCEEDED")
            census[key].extend(entries)
        if not response["IsTruncated"]:
            if response.get("Marker") not in (None, ""):
                _fail("AWS_POLICY_INCOMPLETE")
            break
        marker = _text(response.get("Marker"))
        if marker in markers:
            _fail("AWS_POLICY_INCOMPLETE")
        markers.add(marker)

    entities = {}
    groups = {}
    for kind, key in (
        ("User", "UserDetailList"),
        ("Role", "RoleDetailList"),
        ("Group", "GroupDetailList"),
    ):
        identifiers, names = [], []
        for entity in census[key]:
            name = _text(entity.get(f"{kind}Name"), 128 if kind == "Group" else 64)
            path = _text(entity.get("Path"), 512)
            arn = _text(entity.get("Arn"))
            identifier = _text(entity.get(f"{kind}Id"), 128)
            if (
                not _NAME.fullmatch(name)
                or not re.fullmatch(r"/[\x21-\x7e]*/|/", path)
                or not re.fullmatch(r"[A-Za-z0-9]+", identifier)
                or arn != f"arn:aws:iam::{enrollment.account_id}:{kind.lower()}{path}{name}"
            ):
                _fail("AWS_POLICY_INCOMPLETE")
            if arn in entities:
                _fail("AWS_POLICY_INCOMPLETE")
            entities[arn] = (kind, entity)
            identifiers.append(identifier)
            names.append(name)
            if kind == "Group":
                groups[name] = arn
        _unique(identifiers)
        _unique(names)
        if kind != "Group":
            expected = {entry["arn"]: entry for entry in metadata_capture[f"{kind.lower()}s"]}
            actual = {entity["Arn"]: entity for entity in census[key]}
            if actual.keys() != expected.keys():
                _fail("AWS_POLICY_INCOMPLETE")
            for arn, entity in actual.items():
                other = expected[arn]
                if (
                    entity[f"{kind}Id"] != other[f"{kind.lower()}id"]
                    or entity[f"{kind}Name"] != other["name"]
                    or entity["Path"] != other["path"]
                    or _date(entity.get("CreateDate")) != other["createdate"]
                ):
                    _fail("AWS_POLICY_INCOMPLETE")

    managed = {}
    policy_fingerprints = []
    statements = 0
    inline_count = 0

    def parse(document):
        nonlocal statements
        result = _document(document)
        statements += len(result[0])
        if statements > enrollment.max_policy_statements:
            _fail("AWS_POLICY_LIMIT_EXCEEDED")
        return result

    policy_ids = []
    for policy in census["Policies"]:
        arn = _policy_arn(enrollment, policy.get("Arn"))
        name = _text(policy.get("PolicyName"), 128)
        if not _NAME.fullmatch(name) or arn.rsplit("/", 1)[-1] != name or arn in managed:
            _fail("AWS_POLICY_INCOMPLETE")
        identifier = _text(policy.get("PolicyId"), 128)
        if not re.fullmatch(r"[A-Za-z0-9]+", identifier):
            _fail()
        policy_ids.append(identifier)
        version_id = _text(policy.get("DefaultVersionId"), 128)
        if not re.fullmatch(r"v[1-9][0-9]*(?:\.[A-Za-z0-9-]*)?", version_id):
            _fail()
        versions = _list(policy, "PolicyVersionList")
        defaults, seen = [], set()
        for version in versions:
            if type(version) is not dict or type(version.get("IsDefaultVersion")) is not bool:
                _fail()
            identifier = _text(version.get("VersionId"), 128)
            if identifier in seen:
                _fail("AWS_POLICY_INCOMPLETE")
            seen.add(identifier)
            if version["IsDefaultVersion"]:
                defaults.append(version)
        if len(defaults) != 1 or defaults[0]["VersionId"] != version_id:
            _fail("AWS_POLICY_INCOMPLETE")
        parsed = parse(defaults[0].get("Document"))
        managed[arn] = (name, parsed)
        policy_fingerprints.append(
            {
                "arn": arn,
                "id": policy["PolicyId"],
                "name": name,
                "defaultVersionId": version_id,
                "documentHash": parsed[3],
            }
        )
    _unique(policy_ids)

    own = {}
    boundaries = set()
    memberships = {}
    entity_fingerprints = []
    for arn, (kind, entity) in entities.items():
        policies = []
        names = []
        inline_fingerprints = []
        for policy in _list(entity, f"{kind}PolicyList"):
            if type(policy) is not dict:
                _fail()
            name = _text(policy.get("PolicyName"), 128)
            if not _NAME.fullmatch(name):
                _fail()
            names.append(name)
            inline_count += 1
            if inline_count > enrollment.max_items:
                _fail("AWS_POLICY_LIMIT_EXCEEDED")
            parsed = parse(policy.get("PolicyDocument"))
            policies.append(parsed)
            inline_fingerprints.append({"name": name, "documentHash": parsed[3]})
        _unique(names)
        attached = []
        for attachment in _list(entity, "AttachedManagedPolicies"):
            if type(attachment) is not dict:
                _fail()
            policy_arn = _policy_arn(enrollment, attachment.get("PolicyArn"))
            if policy_arn not in managed or attachment.get("PolicyName") != managed[policy_arn][0]:
                _fail("AWS_POLICY_INCOMPLETE")
            attached.append(policy_arn)
            policies.append(managed[policy_arn][1])
        _unique(attached)
        own[arn] = policies
        if "PermissionsBoundary" in entity:
            boundary = entity["PermissionsBoundary"]
            if (
                kind == "Group"
                or type(boundary) is not dict
                or boundary.get("PermissionsBoundaryType") != "PermissionsBoundaryPolicy"
            ):
                _fail()
            policy_arn = _policy_arn(enrollment, boundary.get("PermissionsBoundaryArn"))
            if policy_arn not in managed:
                _fail("AWS_POLICY_INCOMPLETE")
            boundaries.add(arn)
        if kind == "User":
            names = _list(entity, "GroupList")
            for name in names:
                _text(name, 128)
                if name not in groups:
                    _fail("AWS_POLICY_INCOMPLETE")
            _unique(names)
            memberships[arn] = [groups[name] for name in names]
        entity_fingerprints.append(
            {
                "arn": arn,
                "id": entity[f"{kind}Id"],
                "name": entity[f"{kind}Name"],
                "path": entity["Path"],
                "inlinePolicies": sorted(inline_fingerprints, key=lambda item: item["name"]),
                "attachedPolicies": sorted(attached),
                "groups": sorted(memberships.get(arn, [])),
                "boundary": entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
            }
        )

    principals, edges = [], []
    evaluations = 0
    output_size = 512

    def append_output(target, item):
        nonlocal output_size
        output_size += len(_json(item)) + 1
        if output_size > enrollment.max_capture_bytes:
            _fail("AWS_POLICY_LIMIT_EXCEEDED")
        target.append(item)

    buckets = sorted(bucket["Arn"] for bucket in metadata_capture["buckets"])
    for arn in sorted(entities):
        if entities[arn][0] == "Group":
            continue
        policies = list(own[arn])
        for group in memberships.get(arn, []):
            policies.extend(own[group])
        evaluations += max(1, sum(item[2] for item in policies)) * len(buckets) * len(MAPPINGS)
        if evaluations > enrollment.max_policy_evaluations:
            _fail("AWS_POLICY_LIMIT_EXCEEDED")
        unsupported = any(item[1] for item in policies)
        status = (
            "boundary_unresolved"
            if arn in boundaries
            else "unsupported"
            if unsupported
            else "mapped"
        )
        append_output(
            principals, {"arn": arn, "boundaryPresent": arn in boundaries, "status": status}
        )
        if status != "mapped":
            continue
        policy_map = {str(index): item[0] for index, item in enumerate(policies)}
        for relationship, permission in MAPPINGS:
            for bucket in buckets:
                # One pair at a time prevents an upstream wildcard expansion
                # from allocating all output before our edge/byte limit applies.
                mapped = calculate_permission_relationships(
                    {arn: policy_map}, [bucket], [permission]
                )
                if not mapped:
                    continue
                edge = mapped[0]
                keys = edge["condition_keys"]
                if len(keys) > 128:
                    _fail("AWS_POLICY_LIMIT_EXCEEDED")
                append_output(
                    edges,
                    {
                        "principalArn": arn,
                        "bucketArn": edge["resource_arn"],
                        "relationship": relationship,
                        "hasCondition": edge["has_condition"],
                        "conditionKeys": keys,
                        "resourceScope": "bucket_summary",
                        "assessment": "unknown",
                    },
                )
                if len(edges) > enrollment.max_policy_edges:
                    _fail("AWS_POLICY_LIMIT_EXCEEDED")
    fingerprint = {
        "entities": sorted(entity_fingerprints, key=lambda item: item["arn"]),
        "managedPolicies": sorted(policy_fingerprints, key=lambda item: item["arn"]),
    }
    result = {
        "schemaVersion": 1,
        "assessment": "unknown",
        "mappingVersion": MAPPING_VERSION,
        "policyHash": sha256(_json(fingerprint)).hexdigest(),
        "principals": principals,
        "edges": sorted(
            edges, key=lambda item: (item["principalArn"], item["bucketArn"], item["relationship"])
        ),
        "counts": {
            "groups": len(groups),
            "managedPolicies": len(managed),
            "inlinePolicies": inline_count,
            "statements": statements,
        },
    }
    return validate_policy_evidence(enrollment, metadata_capture, result)


def validate_policy_evidence(enrollment, metadata_capture, value):
    """Validate the worker/graph boundary without accepting raw provider documents."""
    if (
        not enrollment.include_iam_policy_evidence
        or type(value) is not dict
        or set(value)
        != {
            "schemaVersion",
            "assessment",
            "mappingVersion",
            "policyHash",
            "principals",
            "edges",
            "counts",
        }
    ):
        _fail()
    if (
        type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
        or value["assessment"] != "unknown"
        or value["mappingVersion"] != MAPPING_VERSION
        or type(value["policyHash"]) is not str
        or not _HASH.fullmatch(value["policyHash"])
    ):
        _fail()
    counts = value["counts"]
    if type(counts) is not dict or set(counts) != {
        "groups",
        "managedPolicies",
        "inlinePolicies",
        "statements",
    }:
        _fail()
    for key, count in counts.items():
        if type(count) is not int or count < 0:
            _fail()
        if count > (
            enrollment.max_policy_statements if key == "statements" else enrollment.max_items
        ):
            _fail("AWS_POLICY_LIMIT_EXCEEDED")
    expected = {item["arn"] for key in ("roles", "users") for item in metadata_capture[key]}
    if counts["groups"] + counts["managedPolicies"] + len(expected) > enrollment.max_items:
        _fail("AWS_POLICY_LIMIT_EXCEEDED")
    buckets = {item["Arn"] for item in metadata_capture["buckets"]}
    principals, seen = [], {}
    if type(value["principals"]) is not list or len(value["principals"]) != len(expected):
        _fail("AWS_POLICY_INCOMPLETE")
    for principal in value["principals"]:
        if type(principal) is not dict or set(principal) != {"arn", "boundaryPresent", "status"}:
            _fail()
        arn = _text(principal["arn"])
        if arn not in expected or arn in seen:
            _fail("AWS_POLICY_INCOMPLETE")
        if (
            type(principal["boundaryPresent"]) is not bool
            or principal["status"] not in ("mapped", "boundary_unresolved", "unsupported")
            or principal["boundaryPresent"] != (principal["status"] == "boundary_unresolved")
        ):
            _fail()
        seen[arn] = principal["status"]
        principals.append(dict(principal))
    if type(value["edges"]) is not list:
        _fail()
    if len(value["edges"]) > enrollment.max_policy_edges:
        _fail("AWS_POLICY_LIMIT_EXCEEDED")
    edges, identifiers = [], set()
    for edge in value["edges"]:
        if type(edge) is not dict or set(edge) != {
            "principalArn",
            "bucketArn",
            "relationship",
            "hasCondition",
            "conditionKeys",
            "resourceScope",
            "assessment",
        }:
            _fail()
        principal = _text(edge["principalArn"])
        bucket = _text(edge["bucketArn"])
        if (
            seen.get(principal) != "mapped"
            or bucket not in buckets
            or type(edge["relationship"]) is not str
            or edge["relationship"] not in {item[0] for item in MAPPINGS}
            or type(edge["hasCondition"]) is not bool
            or edge["resourceScope"] != "bucket_summary"
            or edge["assessment"] != "unknown"
        ):
            _fail()
        keys = edge["conditionKeys"]
        if type(keys) is not list or len(keys) > 128:
            _fail()
        for key in keys:
            _text(key, 256)
        if keys != sorted(set(keys)) or edge["hasCondition"] != bool(keys):
            _fail()
        identifier = (principal, bucket, edge["relationship"])
        if identifier in identifiers:
            _fail()
        identifiers.add(identifier)
        edges.append({**edge, "conditionKeys": list(keys)})
    if edges and not counts["statements"]:
        _fail()
    if any(item["boundaryPresent"] for item in principals) and not counts["managedPolicies"]:
        _fail()
    if len(_json(value)) > enrollment.max_capture_bytes:
        _fail("AWS_POLICY_LIMIT_EXCEEDED")
    return {
        **value,
        "principals": sorted(principals, key=lambda item: item["arn"]),
        "edges": sorted(
            edges, key=lambda item: (item["principalArn"], item["bucketArn"], item["relationship"])
        ),
        "counts": dict(counts),
    }
