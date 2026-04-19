"""Argos corpus — plugin source acquisition from wordpress.org.

The bounty wedge: top WordPress hunters don't use Burp. They download
plugin ZIPs from wp.org, grep for dangerous sinks, and trace to exploit.
Argos automates that loop at scale.

This package fetches and caches plugin source from the public
wordpress.org SVN/CDN so the AST scanners can operate on real code.
"""

from amoskys.agents.Web.argos.corpus.wporg_svn import (
    PluginSource,
    WPOrgCorpus,
    WPOrgCorpusError,
)

__all__ = ["WPOrgCorpus", "PluginSource", "WPOrgCorpusError"]
