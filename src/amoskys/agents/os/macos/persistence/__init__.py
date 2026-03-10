"""AMOSKYS macOS Persistence Observatory.

Monitors all macOS persistence mechanisms — LaunchAgents, LaunchDaemons,
Login Items, cron jobs, shell profiles, SSH keys, authorization plugins,
folder actions, system extensions, and periodic scripts.

Ground truth (macOS 26.0, uid=501):
    - 6 user LaunchAgents in ~/Library/LaunchAgents/
    - 4 system LaunchAgents in /Library/LaunchAgents/
    - 9 LaunchDaemons in /Library/LaunchDaemons/
    - crontab -l: own-user cron accessible
    - ~/.zshrc, ~/.bashrc: full read access
    - ~/.ssh/authorized_keys: full read access
    - /Library/Security/SecurityAgentPlugins/: readable
    - /Library/SystemExtensions/: readable
    - /etc/periodic/{daily,weekly,monthly}: readable

Coverage: T1543, T1053, T1546, T1547, T1098
"""

from amoskys.agents.os.macos.persistence.agent import MacOSPersistenceAgent

__all__ = ["MacOSPersistenceAgent"]
