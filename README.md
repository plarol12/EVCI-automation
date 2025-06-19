    # EVCI Automated Patching (Tower Workflow)

    ## Components
    * **simulation/attacker_al_47.py** – attacker path & CVE extraction
    * **playbooks/run_simulation.yml** – executes the simulation, generates `vars/cves.yml`
    * **playbooks/patch-cves.yml** – installs packages mapped to CVEs
    * **vars/cves.yml** – created at runtime, consumed by patch playbook
    * **inventory/inventory.ini** – example static inventory for EVCI nodes

    ## Tower Setup
    1. Create a Project pointing to this repository.
    2. Import inventory or use dynamic source.
    3. Job Template A: `run_simulation.yml` (Survey: entry_point, attacker_algo, weighted)
    4. Job Template B: `patch-cves.yml` (no survey, uses vars file)
    5. Workflow: A -> B (Always).
    6. Schedule the workflow or run on demand.

    ## Surveys
    Example JSON for Survey:
    ```json
    [
      {
        "type": "text",
        "question_name": "survey_entry_point",
        "question_description": "Entry point for attacker (e.g., CSMS)",
        "default": "CSMS",
        "required": true
      },
      {
        "type": "multiplechoice",
        "question_name": "survey_attacker_algo",
        "choices": "bfs
dijkstra
stealth",
        "default": "bfs",
        "required": true
      },
      {
        "type": "multiplechoice",
        "question_name": "survey_weighted",
        "choices": "true
false",
        "default": "false",
        "required": true
      }
    ]
    ```

    ## Extending patch_map
    Edit `patch-cves.yml` or externalize patch_map via variable files
    to map additional CVEs to package names or custom patch scripts.
