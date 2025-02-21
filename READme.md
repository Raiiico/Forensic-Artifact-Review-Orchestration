## Mini Project 2: Forensic Analysis Orchestration

### 1. Project Overview
The Forensic Analysis Orchestration automates the process of analyzing digital forensic artifacts, focusing on system behavior and user activity. This project leverages RECmd, JLECmd, and MFTECmd to process registry hives, jump lists, and master file tables, respectively. The results are consolidated into a single CSV report and organized into a dedicated folder for individual tool outputs.

### 2. Purpose
The primary objective of this orchestration is to streamline the forensic investigation workflow by:
- Automating the execution of forensic tools.
- Generating consolidated findings in `System_Behavior_Review.csv`.
- Organizing individual tool outputs into the `Tool_Outputs` folder.

### 3. Workflow Overview
1. **Artifact Collection:** Forensic artifacts are placed in the `Forensic_Evidence` directory.
2. **Tool Execution:**
   - `RECmd`: Analyzes registry hives using the `UserActivity.reb` batch file.
   - `JLECmd`: Processes jump lists (`AutomaticDestinations` and `CustomDestinations`).
   - `MFTECmd`: Analyzes the Master File Table (`$MFT`).
3. **Result Consolidation:**
   - Outputs are processed into individual CSV files.
   - `JLECmd` results are combined into `JLECmd_Results.csv`.
   - The final report, `System_Behavior_Review.csv`, consolidates all findings.
4. **Output Organization:** All individual CSV outputs are moved to the `Tool_Outputs` folder.

### 4. Directory Structure
```
MiniProject2
│
├── Forensic_Evidence
│   ├── Registry
│   ├── JumpLists
│   └── FileSystem
│
├── Forensics_Results
│   ├── System_Behavior_Review.csv
│   └── Tool_Outputs
│       ├── RECmd_Results.csv
│       ├── JLECmd_Results.csv
│       └── MFTECmd_Results.csv
│
└── UserActivity.reb (Batch file for RECmd)
```

### 5. Execution Steps
1. Place forensic artifacts in the `Forensic_Evidence` folder.
2. Ensure `UserActivity.reb` is in the working directory.
3. Run the `ez_orchestrator.py` script.
4. Review the `System_Behavior_Review.csv` and `Tool_Outputs` folder in `Forensics_Results`.

### 6. Conclusion
This orchestration simplifies forensic analysis by automating artifact processing, consolidating findings, and maintaining organized outputs. It enhances efficiency and ensures comprehensive review of system behavior and user activity.
