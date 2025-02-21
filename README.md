# Forensic-Artifact-Review-Orchestration
Automated forensic artifact review using Eric Zimmerman's RECmd, JLECmd, and MFTECmd for user activity and system behavior analysis.

## 🚀 Features

- **Automated Artifact Analysis:** Runs RECmd, JLECmd, and MFTECmd on collected artifacts.
- **Consolidated Report:** Merges results into a single `System_Behavior_Review.csv`.
- **Key Findings Summary:** Generates `Summary_Report.csv` highlighting critical insights.
- **Organized Outputs:** Stores individual tool outputs in `Tool_Outputs/` for detailed review.

---

## 📦 Installation

1. **Clone the Repository:**

```bash
git clone https://github.com/yourusername/Forensic-Artifact-Review-Orchestration.git
cd Forensic-Artifact-Review-Orchestration
```
---

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
Forensic-Artifact-Review-Orchestration/
├── Forensic_Evidence/            # User-provided artifacts (Registry, JumpLists, MFT)
├── Forensics_Results/            # Output folder for results and reports
│   ├── System_Behavior_Review.csv  # Final consolidated report
│   ├── Summary_Report.csv          # Highlighted key findings
│   └── Tool_Outputs/               # Individual tool outputs (.csv)
├── UserActivity.reb               # RECmd batch file
├── ez_orchestrator.py             # Main Python script
└── README.md                      # Project description and usage
```

### 5. Execution Steps
1. Place forensic artifacts in the `Forensic_Evidence` folder.
2. Ensure `UserActivity.reb` is in the working directory.
3. Run the `ez_orchestrator.py` script.
4. Review the `System_Behavior_Review.csv` and `Tool_Outputs` folder in `Forensics_Results`.

### 6. Conclusion
This orchestration simplifies forensic analysis by automating artifact processing, consolidating findings, and maintaining organized outputs. It enhances efficiency and ensures a comprehensive review of system behavior and user activity.

