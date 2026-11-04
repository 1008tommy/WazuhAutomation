# Portable CALDERA lab scenarios

This bundle lets a teammate recreate the four Windows lab profiles on a separate CALDERA 5.x server. It contains four adversary files, nine custom ability files, one `Thief-Lab` fact source, and uses the versioned `../required-payloads/lab-note.ps1`. The two remaining Thief-Lab abilities (`300157e5-...` and `ea713bc4-...`) are supplied by the Stockpile plugin.

Stockpile is a core CALDERA plugin that supplies abilities, parsers, requirements, facts, and the atomic planner used by these profiles. This bundle requires it; the `install_bundle.py` script checks that its directory exists. On a Git checkout of CALDERA, check and initialize the pinned submodule before installing the bundle:

```bash
cd "$HOME/caldera"
test -f plugins/stockpile/hook.py && echo 'Stockpile files present' || git submodule update --init plugins/stockpile
grep -n 'stockpile' conf/local.yml conf/default.yml 2>/dev/null
```

The active CALDERA configuration must list `stockpile` under `plugins:`. If the files are present but Stockpile is not enabled, edit the active configuration while CALDERA is stopped, then restart it. If this is a Docker or packaged installation rather than a Git checkout, install/enable Stockpile using that installation's plugin procedure; do not run the submodule command against a non-Git directory.

**Provenance:** the ability files were reconstructed from the adversary UI exports in `Scenarios/` plus the parser and cleanup settings documented in `Scenarios/README.md`. They are not a byte-for-byte backup of the original server's `data/abilities` files. Compare them with those files if an exact migration is required. The original adversary exports are kept unchanged.

## Install on a test CALDERA server

1. Use a CALDERA installation with Stockpile enabled; the [lab's CALDERA 5.3.0 setup](../../README.md#caldera-530-lab-installation) is documented in this repository. Stop CALDERA before copying data files. From the CALDERA server's shell, clone the scenario branch **outside** the `~/caldera` directory:

   ```bash
   git clone --branch caldera-portable-lab-bundle --single-branch https://github.com/1008tommy/WazuhAutomation.git "$HOME/WazuhAutomation"
   ```

   If `~/WazuhAutomation` already exists, update that checkout to this branch instead of cloning over it.

2. If your CALDERA checkout is `~/caldera`, run this command from any directory:

   ```bash
   python "$HOME/WazuhAutomation/Scenarios/portable/install_bundle.py" --caldera-root "$HOME/caldera"
   ```

   The installer checks both folders before copying. It preserves tactic subfolders, skips identical files, and stops if an existing destination file differs. No `sudo` is needed when your account owns the CALDERA checkout.

3. Confirm the two Stockpile ability IDs listed above exist on that CALDERA server. If they do not, check the Stockpile version before running Thief-Lab.
4. Restart CALDERA. Verify the four adversary profiles list the expected ability names and that each ability's Windows `psh` executor has the command, parser, requirement, and cleanup shown in its bundle file. The Fact Sources page should show `Thief-Lab` with `file.sensitive.extension = txt` and score `11`.
5. On the isolated Windows test VM, create `C:\BASLab`. For Thief-Lab, place exactly one synthetic `.txt` file in `C:\BASLab\input` and **select the `Thief-Lab` fact source when creating the operation**. Installing a source makes it available in CALDERA; it does not automatically attach it to an operation. The other three profiles do not require a starting fact. Run one profile at a time with the atomic planner, cleanup enabled, and a Windows agent that supports `psh`.

For File Delivery and Execution Lab, the bundled download ability uses `#{server}/file/download`, so CALDERA supplies its server address. Confirm that address is reachable from the Windows agent. Do not run these on production endpoints or with real sensitive files.

## Update an existing installation

Stop CALDERA, then pull and apply any bundle updates:

```bash
git -C "$HOME/WazuhAutomation" pull --ff-only
python3 "$HOME/WazuhAutomation/Scenarios/portable/install_bundle.py" --caldera-root "$HOME/caldera" --upgrade
```

Restart CALDERA afterward. The installer adds newly published files, including the `Thief-Lab` fact source. `--upgrade` can also replace the four faulty ability files from the first bundle release, but only when their hashes match that release. It refuses to overwrite files edited independently. Existing adversary profiles do not need to be imported again.

## Local check

With Python 3 and PyYAML installed, from the repository root run:

```text
python -m pip install -r Scenarios/portable/requirements.txt
python Scenarios/portable/check_bundle.py
```

The check parses all bundle YAML, confirms that every profile references an included ability or one of the two declared Stockpile IDs, and verifies the known cleanup, parser, and fact-source settings. It cannot test the CALDERA loader, agent execution, or Wazuh detection; those need a lab run on the destination server.

`build_bundle.py` regenerates these files from the UI exports. It adds the settings omitted by those exports. Review its `EXTRAS` mapping before regenerating if the source CALDERA abilities have changed.

## What to send back after testing

For each profile, record the operation ID, the ability statuses, cleanup statuses, and whether the expected marker or archive was produced. Note CALDERA version and any missing or skipped ability. See `../README.md` for each scenario's endpoint checks and manual cleanup.
