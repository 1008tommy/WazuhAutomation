# Scenario specs

Each JSON file wires one lab scenario to the Caldera v2 API. A spec names an adversary that the
portable bundle has already installed in Caldera (`Scenarios/portable/install_bundle.py`), so the
runner only launches and scores it; it does not define new techniques or payloads.

Fields:
- `scenario`  short id, used in run-folder names
- `name`      human name (matches the Caldera adversary)
- `adversary_id`  the bundle adversary to run
- `planner`   resolved by name through `GET /api/v2/planners` (do not hardcode the id)
- `source`    fact source id, or `null` for the stock `basic` source
- `obfuscator`  must be `plain-text` (the goal is to measure detection, not evade it)
- `jitter`, `expected_techniques`

Prerequisites on the Caldera server (once per snapshot): the bundle installed, Caldera running in
tmux, and the Sandcat agent checked in on `WIN11-TEST01` in group `red`.

Run one scenario end to end (launch, verify cleanup, collect, score, refresh the dashboard):

    python run_scenario.py scenarios/discovery.json --collect

Without `--collect` the runner launches and verifies cleanup, then prints the `collect_operation.py`
command to run next. The runner refuses to start if any host other than `WIN11-TEST01` is in group
`red`, if the agent is untrusted or stale, or if a spec asks for anything but the plain-text obfuscator.

| Spec | Adversary | Techniques |
|---|---|---|
| discovery.json | Discovery Scenario | T1033, T1087.001, T1057, T1135, T1018, T1518.001, T1069 |
| scheduled-task.json | Scheduled Task Creation | T1053.005 |
| renamed-utility.json | Renamed Utility Lab | T1036.003 |
| file-delivery.json | File Delivery and Execution Lab | T1105, T1059.001 |
| thief-lab.json | Thief-Lab | T1074.001, T1005, T1560.001, T1041 |

`thief-lab.json` resolves the dedicated `Thief-Lab` fact source by its installed ID or name, checks
that it contains one `file.sensitive.extension` fact, and verifies CALDERA selected that source for
the operation. The dashboard log prints the selected extension before launch. Revert
`WIN11-TEST01` to its snapshot if the runner reports a cleanup failure.
