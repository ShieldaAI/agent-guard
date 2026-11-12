"""Typed shapes of the JSON records that cross module boundaries.

These describe values that have already been validated: the inventory snapshot, the
archive's receipt, health and lifecycle files, and the command results built from
them. They carry no behaviour and perform no validation.
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

Profile = Literal["core", "host", "host-mcp"]
ReceiptStatus = Literal["pending", "published", "idempotent"]


class Source(TypedDict):
    """The exact five-field identity of one enrolled inventory source."""

    companyId: str
    sourceId: str
    enrollmentGeneration: str
    inventoryInstanceId: str
    tenantId: str


class Snapshot(TypedDict):
    """One validated inventory snapshot (schema v1 or v2); see the JSON schemas."""

    schemaVersion: int
    profile: Profile
    source: Source
    snapshotId: str
    generatedAt: str
    ledgerRevision: int
    policyEpoch: int
    coverage: dict[str, Any]
    tasks: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    untrustedContextDefault: NotRequired[bool | None]
    manifest: NotRequired[dict[str, Any]]
    mcp: NotRequired[dict[str, Any]]


class ReceiptRecord(TypedDict):
    """``<receipt id>.receipt.json``: one stored snapshot and its publication outcome."""

    schemaVersion: int
    receiptId: str
    source: Source
    sourceId: str
    profile: Profile
    snapshotId: str
    sha256: str
    createdAt: int
    status: ReceiptStatus
    publishedAt: int | None
    publicationSequence: int | None
    projectionId: str | None
    lastError: str | None


class HealthRecord(TypedDict):
    """``health-<source id>.json``: the latest attempt and success for one source."""

    schemaVersion: int
    sourceId: str
    profile: Profile
    lastAttemptAt: int
    lastSuccessAt: int | None
    lastError: str | None
    consecutiveFailures: int
    lastSnapshotId: str | None
    lastSnapshotGeneratedAt: str | None
    lastProjectionId: str | None


class Transition(TypedDict):
    """A host-approved replacement of one source generation by another."""

    schemaVersion: int
    predecessor: Source
    successor: Source
    profile: Profile


class TransitionReceipt(TypedDict):
    """The graph's record that a predecessor was superseded."""

    schemaVersion: int
    transitionId: str
    predecessorSourceId: str
    successorSourceId: str
    profile: Profile
    supersededAtMs: int


class TransitionRecord(TypedDict):
    """``lifecycle-<predecessor id>.json``: a pending intent or a completed transition."""

    schemaVersion: int
    transition: Transition
    transitionId: str
    status: Literal["pending", "complete"]
    receipt: TransitionReceipt | None


class DiscardResult(TypedDict):
    """What ``SnapshotArchive.discard`` removed."""

    receiptId: str
    state: Literal["pending", "uncertain", "damaged", "orphan"]
    sourceId: str | None
    snapshotId: str | None


class BackupFile(TypedDict):
    """One file named by a backup manifest."""

    name: str
    size: int
    sha256: str


class BackupSource(TypedDict):
    """One source a backup covers."""

    source: Source
    profile: Profile


class BackupManifest(TypedDict):
    """``backup.json``: the closed file set of one collector backup."""

    format: str
    schemaVersion: int
    backupId: str
    createdAt: int
    sources: list[BackupSource]
    files: list[BackupFile]
