"""Azure API adapters: authentication, Resource Graph, Container Registry.

All modules here talk to Azure via official SDKs — never via
``subprocess.run(["az", ...])``. See ``docs/python-architecture.md`` §2.
"""
