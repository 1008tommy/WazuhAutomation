# WazuhAutomation

This repository contains [CALDERA lab scenarios](Scenarios/README.md), a [portable scenario bundle](Scenarios/portable/README.md), and [scripts for collecting CALDERA and Wazuh detection evidence](caldera-wazuh-automatic-collection/automatic-collection/README.md).

## CALDERA 5.3.0 lab installation

These are the steps used to set up the isolated Ubuntu CALDERA lab. They are installation notes for a fresh VM; an existing CALDERA server does not need to be reinstalled to use the scenario bundle.

1. Update Ubuntu, then reconnect after the reboot:

   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo reboot
   ```

2. Install the prerequisites, including Go for building Sandcat agents and `tmux` for keeping the server session alive:

   ```bash
   sudo apt install -y git curl ca-certificates build-essential python3-pip python3-venv golang-go tmux
   ```

3. Install Node.js 22 from NodeSource and check its version:

   ```bash
   curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/nodesource_setup.sh
   sudo -E bash /tmp/nodesource_setup.sh
   sudo apt install -y nodejs
   node --version
   ```

   This lab used Node.js 22 after the Ubuntu-packaged Node.js 18 failed its frontend build. CALDERA's published v5.3.0 minimum is Node.js 16; Node.js 22 is the version used for this lab, not a general minimum.

4. Clone the CALDERA 5.3.0 release and its plugin submodules:

   ```bash
   cd "$HOME"
   git clone --recursive --branch 5.3.0 https://github.com/mitre/caldera.git
   cd caldera
   ```

   `--recursive` fetches plugins such as Stockpile. The release tag pins CALDERA and its submodule revisions.

5. Install Python dependencies in a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   python -m pip install -r requirements.txt
   ```

   The virtual environment keeps CALDERA's Python packages separate from the system installation.

6. Start a `tmux` session, then build and start CALDERA inside it:

   ```bash
   tmux new -s caldera
   ```

   In the new `tmux` session:

   ```bash
   cd "$HOME/caldera"
   source venv/bin/activate
   python3 server.py --insecure --build
   ```

   Wait for `All systems ready`. `--build` builds the web interface on first start or after frontend changes. `--insecure` uses `conf/default.yml` and its default credentials, so this mode is for the isolated lab only. To leave the server running after SSH disconnects, detach with **Ctrl+B**, then **D**. Reconnect with `tmux attach -t caldera`.

CALDERA installation and configuration references: [v5.3.0 installation guide](https://caldera.readthedocs.io/en/5.3.0/Installing-Caldera.html) and [server configuration](https://caldera.readthedocs.io/en/5.3.0/Server-Configuration.html).
