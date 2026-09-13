"""Azure authentication — single ``DefaultAzureCredential`` shared by
Resource Graph and Container Registry clients.

The chain (in order tried by DefaultAzureCredential):

    1. Env vars (AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET)
    2. Managed identity (in-cluster / VM)
    3. Azure CLI cache (``az login`` — dev laptop path)
    4. Visual Studio / VS Code cached credentials
    5. Interactive browser (last resort)

Prerequisite: the identity needs **Security Reader at tenant scope** so
``microsoft.security/cvedetails`` enrichment is visible (see erros.md).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential


def get_credential() -> TokenCredential:
    """Return a ``DefaultAzureCredential`` — same instance can back both
    the Resource Graph client and the Container Registry client.

    Import is deferred so the module loads without extras installed —
    tests that don't touch auth don't need the SDK.
    """
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def get_subscription_ids() -> list[str]:
    """Discover subscription IDs the current identity can read.

    Used by the Resource Graph client so we don't have to pass
    subscription IDs from CLI args. If the SDK is not installed or the
    identity has no subscriptions, returns an empty list — caller
    treats empty as "default scope" (ARG queries then run against all
    accessible subs).
    """
    try:
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        return []
    try:
        client = SubscriptionClient(get_credential())
        return [sub.subscription_id for sub in client.subscriptions.list() if sub.subscription_id]
    except Exception:
        return []
