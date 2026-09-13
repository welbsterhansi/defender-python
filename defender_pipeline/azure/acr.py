"""Azure Container Registry data-plane wrapper.

Uses ``azure.containerregistry.ContainerRegistryClient`` for tag/manifest
listing — replaces ``az acr repository show-tags --detail`` from the
bash pipeline.

Design:
  * :class:`AcrTagResolver` builds a ``{repo@digest: tag}`` cache.
  * Failure to list tags for a given repo (403 RBAC, or repo missing)
    is caught and logged as a WARN — the caller falls back to
    ``TAG=N/A`` for that repo's digests. Never aborts the scan.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

log = logging.getLogger("defender_pipeline.azure.acr")


class AcrTagResolver:
    """Resolves image tags for a set of (repository, digest) pairs.

    One SDK call per unique repository — the response for a repo
    contains ALL its manifests, so we cache everything in one pass.
    First-tag-wins per digest (matches the ``[0]`` semantics in
    ``defender.sh``).
    """

    def __init__(self, credential: TokenCredential, acr_name: str) -> None:
        from azure.containerregistry import ContainerRegistryClient
        endpoint = f"https://{acr_name}.azurecr.io"
        self._client = ContainerRegistryClient(endpoint, credential)
        # Public: dict indexable by `f"{repo}@{digest}"` → first tag.
        self.tag_cache: dict[str, str] = {}
        # Track failures so caller can log the count.
        self.failed_repos: set[str] = set()
        self._resolved_repos: set[str] = set()

    def resolve_repos(self, repos: list[str]) -> None:
        """For each unique repo, populate ``tag_cache`` with all its
        (digest → first tag) entries. Failures logged, not raised."""
        for repo in {r for r in repos if r}:
            if repo in self._resolved_repos:
                continue
            self._resolved_repos.add(repo)
            self._resolve_one_repo(repo)

    def _resolve_one_repo(self, repo: str) -> None:
        from azure.core.exceptions import HttpResponseError
        try:
            manifests = list(self._client.list_manifest_properties(repo))
        except HttpResponseError as exc:
            log.warning(
                "show-tags failed for repository=%s — "
                "digests in this repo will use TAG=N/A (status=%s)",
                repo, getattr(exc, "status_code", "?"),
            )
            self.failed_repos.add(repo)
            return
        except Exception as exc:  # pragma: no cover — defensive
            log.warning(
                "show-tags failed for repository=%s — "
                "digests in this repo will use TAG=N/A (%s: %s)",
                repo, type(exc).__name__, exc,
            )
            self.failed_repos.add(repo)
            return

        for manifest in manifests:
            digest = getattr(manifest, "digest", None)
            tags = getattr(manifest, "tags", None) or []
            if not digest or not tags:
                continue
            key = f"{repo}@{digest}"
            # First-tag-wins (matches bash `[0]` semantics).
            if key not in self.tag_cache:
                self.tag_cache[key] = tags[0]

    def get(self, repo: str, digest: str, default: str = "N/A") -> str:
        """Look up the resolved tag, defaulting to ``N/A`` (matches
        ``--skip-tags`` behavior for missing entries)."""
        return self.tag_cache.get(f"{repo}@{digest}", default)
