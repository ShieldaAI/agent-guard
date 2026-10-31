"""Bundle the repository's canonical inventory schema in wheels and source archives."""

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        root = Path(self.root)
        in_repository = root.name == "cartography" and root.parent.name == "integrations"
        prefix = "src/" if self.target_name == "sdist" else ""
        for filename in (
            "agent-guard-inventory-v1.schema.json",
            "agent-guard-inventory-manifest-v1.schema.json",
            "agent-guard-mcp-inventory-v1.schema.json",
        ):
            canonical = root.parent.parent / "schemas" / filename
            packaged = root / "src" / "agent_guard_cartography" / "schemas" / filename
            schema = canonical if in_repository and canonical.is_file() else packaged
            if not schema.is_file():
                raise RuntimeError(
                    "A canonical inventory schema is missing from the source package"
                )
            build_data["force_include"][str(schema)] = (
                f"{prefix}agent_guard_cartography/schemas/{filename}"
            )
        license_file = root.parent.parent / "LICENSE" if in_repository else root / "LICENSE"
        if not license_file.is_file():
            raise RuntimeError("The integration license is missing from the source package")
        license_target = (
            "LICENSE" if self.target_name == "sdist" else "agent_guard_cartography/LICENSE"
        )
        build_data["force_include"][str(license_file)] = license_target
        filename = "aws-permission-relationships.yaml"
        canonical_mapping = root.parent.parent / "deployment" / "cartography" / filename
        packaged_mapping = root / "src" / "agent_guard_cartography" / "data" / filename
        mapping = canonical_mapping if in_repository else packaged_mapping
        if not mapping.is_file():
            raise RuntimeError("The pinned AWS permission mapping is missing")
        build_data["force_include"][str(mapping)] = (
            f"{prefix}agent_guard_cartography/data/{filename}"
        )
