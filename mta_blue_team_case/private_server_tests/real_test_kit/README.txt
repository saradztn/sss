NRTH private-server validation kit  (defender side, v1)
=======================================================
WHAT THIS IS
A runnable kit for the four-person test server, built so that the *validation* is done against the
real environment rather than a simulation, while every program here stays on the defender's side of
the line: server-side Lua + read-only client diagnostics + offline PE analysis. Nothing in this kit
patches, injects into, or reads the memory of a running game process, and nothing suppresses or
forwards anti-cheat traffic.

FILES
  report_counter.lua      MTA:SA server resource (Lua). Counts the four anti-cheat report events per
                          player per minute and writes ac_report_counter.csv + ac_report_alerts.log.
                          The signal it measures is SILENCE: a client whose report functions were
                          neutralised stops sending PLAYER_SCREENSHOT / PLAYER_TRANSGRESSION /
                          PLAYER_DIAGNOSTIC / PLAYER_ACINFO while it stays online and active.
  collect_client.ps1      Run on the test client (PowerShell 5.1+, ordinary user; admin gives more).
                          Read-only: file hashes/versions, module list of the running game process,
                          suspicious paths (C:\ProgramData:NT2, C:\NVX, C:\Overwack\loader_config.cfg),
                          export-directory module name of any nvx/NRTH-like DLL. Writes
                          client_<host>_<utc>.json + .csv to -OutDir. It does not touch game memory.
                          Also writes reportpath_entries.json (the netc.dll export/RVA candidates) so
                          the offline checker can be pointed at them.
  meta.xml                Drop-in for the resource directory (server-side scripts only, no client sync).
  expected_findings.md    What each output must look like for a CLEAN client vs an INFECTED client, and
                          how to feed reportpath_entries.json to
                          recovered_or_reconstructed_project/tools/nrth_report_path_check.py entries.

RUN ORDER
  1. server:  copy report_counter.lua + meta.xml into  mods/deathmatch/resources/nrth_acwatch/
              then  refresh  and  start nrth_acwatch     (writes into that resource's folder)
  2. server:  add  <acl request="resource.nrth_acwatch"><right name="function.setTimer" access="true" /></acl>
              only if your server config restricts timers for resources; the script uses no admin calls.
  3. client:  start the game normally (unpatched baseline), play 5 minutes
  4. client:  powershell -ExecutionPolicy Bypass -File collect_client.ps1 -OutDir C:\acbaseline
  5. compare: run the same two steps while the report path is known to be disturbed, or on the
              reference client that already has the payload, and diff the CSVs
  6. offline: python3 recovered_or_reconstructed_project/tools/nrth_report_path_check.py entries \
                  <netc.dll on disk> --funcs <reportpath_entries.json> --csv entries.csv
              exit 0 = the on-disk entries look intact (expected — the sample patches the LOADED copy,
              so a clean on-disk result does NOT clear the client; combine with steps 1-5 and YARA)
  7. offline: python3 recovered_or_reconstructed_project/tools/nrth_pe_catalog.py
              (rebuilds mta_blue_team_case/imports_exports.txt + strings_catalog.txt for whichever
              PE paths you pass, so a suspect file can be compared field by field with the sample)

LIMITS OF THIS KIT (stated, not hidden)
  - The on-disk check in step 6 cannot see a live one-byte patch; it is a correlation tool, and the
    primary evidence stays server-side report silence (step 1) plus YARA on the client image.
  - Report-event names are the ones the sample's own string table carries (see
    mta_blue_team_case/detection/recovered_strings.txt); if your server build names them differently,
    adjust the EVENTS table at the top of report_counter.lua — the counting logic is unchanged.
  - No component here needs or should get a debugger/admin token on the client. If a step seems to
    require writing into the game directory, that step is out of scope for this case.
