The main usability problems are setting the tool up and working out what to allow, not running the proxy itself. Here's what I'd change, most valuable first.

1. Help users set up and verify containment (biggest gap).
On its own the proxy contains nothing. It only works together with a restricted user, loopback-only firewall rules and file ACLs. The README lists these but gives no commands. If one is missing, nothing errors, so the user believes the agent is contained while it can reach the network directly.
- Setup: add a one-time admin script, or at least the exact New-LocalUser, New-NetFirewallRule and icacls commands.
- Check: add a check command that the agent user runs. It confirms that direct connections fail, the proxy is reachable, and the exe, config and PID directory aren't writable.

2. Shorten the loop for finding which hosts to allow.
Today it's: run the tool, look for decision=deny in the log, edit the JSON by hand, restart. A read-only denied command could read the log and print each blocked target with a count, as entries ready to paste into allowed. It has no security cost. I'd avoid a "learn mode" that allows everything and records it, because that turns off containment exactly while you trust the setup least.

3. Ship ready-made allowlists for common uses.
For example Claude Code, git with GitHub, npm and PyPI. Otherwise every new user finds the hosts by trial and error. This only needs docs or example configs. I'd build the lists with the tool itself (run each use case, collect what's denied) rather than from memory, because the hosts change.

4. Fill gaps in the Quick start.
- NO_PROXY: recommend NO_PROXY=localhost,127.0.0.1. Without it, an agent testing its own local dev server goes through the proxy and gets a 403, because loopback isn't public. That looks like a bug in the tool.
- Clients that ignore the proxy variables: list them, with how to configure each.

5. Allow comments in the config.
Reviewing an allowlist is a security task, and "why is this host here?" is the question that matters. Comments would let each entry carry its reason. There's a cost: you picked JSON so configuration scripts could produce it, so check whether comments would break that.

Out of scope:
- Hot reload. The spec deliberately reads the config once ("No state that changes mid-session"), and restart already covers it.