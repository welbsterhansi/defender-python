"""Kubernetes client factory.

Uses the official ``kubernetes`` Python client. On dev laptops
``load_kube_config()`` reads ``~/.kube/config`` (or ``$KUBECONFIG``);
in-cluster runs use ``load_incluster_config()`` when the service-
account token is mounted at ``/var/run/secrets/kubernetes.io/``.

No ``oc`` subprocess in the main path.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kubernetes.client import CoreV1Api

log = logging.getLogger("defender_pipeline.openshift.client")


def get_core_api(kubeconfig: str | Path | None = None) -> CoreV1Api:
    """Return a ``CoreV1Api`` bound to the current cluster context.

    Try order:
      1. In-cluster config (``load_incluster_config``) — for pod-hosted
         runs where the service-account token is mounted.
      2. ``load_kube_config(config_file=kubeconfig)`` — for dev laptops
         with ``oc login`` or an explicit ``--kubeconfig`` path.

    Raises ``RuntimeError`` with an actionable message if neither works.
    """
    from kubernetes import client, config
    from kubernetes.config.config_exception import ConfigException

    try:
        config.load_incluster_config()
        log.info("kubernetes: using in-cluster service-account config")
    except ConfigException:
        try:
            config.load_kube_config(config_file=str(kubeconfig) if kubeconfig else None)
            log.info("kubernetes: using kubeconfig from %s",
                     kubeconfig or "~/.kube/config or $KUBECONFIG")
        except (ConfigException, FileNotFoundError) as exc:
            raise RuntimeError(
                "kubernetes: no cluster config available — set $KUBECONFIG, "
                "run `oc login`, or pass --kubeconfig. "
                f"({type(exc).__name__}: {exc})",
            ) from exc

    return client.CoreV1Api()
