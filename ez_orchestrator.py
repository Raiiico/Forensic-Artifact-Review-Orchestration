import subprocess
import os
import pandas as pd

# Paths
working_dir = os.getcwd()
artifacts_path = os.path.join(working_dir, "Forensic_Evidence")
output_dir = os.path.join(working_dir, "Forensics_Results")
tool_outputs_dir = os.path.join(output_dir, "Tool_Outputs")
os.makedirs(output_dir, exist_ok=True)
os.makedirs(tool_outputs_dir, exist_ok=True)

output_file = os.path.join(output_dir, "System_Behavior_Review.csv")
summary_file = os.path.join(output_dir, "Summary_Report.csv")

# Artifact paths
artifacts = {
    "Registry": os.path.join(artifacts_path, "Registry"),
    "JumpLists": os.path.join(artifacts_path, "JumpLists"),
    "MFT": os.path.join(artifacts_path, "FileSystem", "$MFT")
}

results = []

# Function to combine JLECmd outputs
def combine_jlecmd_outputs():
    auto_csv = os.path.join(output_dir, "JumpLists_AutomaticDestinations.csv")
    custom_csv = os.path.join(output_dir, "JumpLists_CustomDestinations.csv")
    combined_csv = os.path.join(output_dir, "JLECmd_Results.csv")

    dfs = []

    # Collect AutomaticDestinations
    auto_files = [f for f in os.listdir(output_dir) if "AutomaticDestinations" in f and f.endswith(".csv")]
    for file in auto_files:
        path = os.path.join(output_dir, file)
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                df["Source"] = "AutomaticDestinations"
                dfs.append(df)
            except Exception as e:
                print(f"[❌] Failed to read {file}: {e}")

    # Collect CustomDestinations
    custom_files = [f for f in os.listdir(output_dir) if "CustomDestinations" in f and f.endswith(".csv")]
    for file in custom_files:
        path = os.path.join(output_dir, file)
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                df["Source"] = "CustomDestinations"
                dfs.append(df)
            except Exception as e:
                print(f"[❌] Failed to read {file}: {e}")

    # Combine both into one CSV
    if dfs:
        combined_df = pd.concat(dfs, ignore_index=True)
        combined_df.to_csv(combined_csv, index=False)
        print(f"\n✅ JLECmd results combined into: {combined_csv}")
        results.append(combined_df)

        # Clean up individual outputs
        for file in auto_files + custom_files:
            try:
                os.remove(os.path.join(output_dir, file))
            except Exception as e:
                print(f"[⚠] Failed to remove {file}: {e}")
    else:
        print("[⚠] No valid JLECmd outputs to combine.")

# Function to run tool and collect results
def run_tool(tool_name, cmd, output_csv):
    print(f"\n[+] Running {tool_name}...")
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)

        if result.returncode == 0:
            if os.path.exists(output_csv) and os.path.getsize(output_csv) > 0:
                df = pd.read_csv(output_csv)
                df["Tool"] = tool_name
                results.append(df)
                print(f"[✔] {tool_name} results captured from {output_csv}.")
            else:
                print(f"[❌] {tool_name} generated no results.")
        else:
            print(f"[❌] {tool_name} failed. Error:\n{result.stderr}")
    except Exception as e:
        print(f"[❌] {tool_name} error: {e}")

# Generate Summary Report
def generate_summary():
    print("\n[+] Generating summary report...")
    summary_data = []

    # RECmd Summary
    recmd_csv = os.path.join(output_dir, "RECmd_Results.csv")
    if os.path.exists(recmd_csv):
        try:
            recmd_df = pd.read_csv(recmd_csv)
            if not recmd_df.empty:
                summary_data.append({"Tool": "RECmd", "Key Finding": f"{len(recmd_df)} registry-related events detected."})
        except Exception as e:
            print(f"[❌] Failed to summarize RECmd results: {e}")

    # JLECmd Summary
    jlecmd_csv = os.path.join(output_dir, "JLECmd_Results.csv")
    if os.path.exists(jlecmd_csv):
        try:
            jlecmd_df = pd.read_csv(jlecmd_csv)
            top_interactions = jlecmd_df.groupby('Path').size().sort_values(ascending=False).head(5)
            for path, count in top_interactions.items():
                summary_data.append({"Tool": "JLECmd", "Key Finding": f"File '{path}' accessed {count} times."})
        except Exception as e:
            print(f"[❌] Failed to summarize JLECmd results: {e}")

    # MFTECmd Summary
    mftecmd_csv = os.path.join(output_dir, "MFTECmd_Results.csv")
    if os.path.exists(mftecmd_csv):
        try:
            mfte_df = pd.read_csv(mftecmd_csv)
            recent_files = mfte_df.head(5)
            for _, row in recent_files.iterrows():
                summary_data.append({"Tool": "MFTECmd", "Key Finding": f"File '{row['FileName']}' was recently created, modified, or deleted."})
        except Exception as e:
            print(f"[❌] Failed to summarize MFTECmd results: {e}")

    # Write summary
    if summary_data:
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_csv(summary_file, index=False)
        print(f"\n✅ Summary report generated at: {summary_file}")
    else:
        print("\n⚠ No key findings to summarize.")

# RECmd Execution
if os.path.isdir(artifacts["Registry"]):
    recmd_csv = os.path.join(output_dir, "RECmd_Results.csv")
    batch_file = os.path.join(working_dir, "UserActivity.reb")

    if os.path.exists(batch_file):
        run_tool(
            "RECmd",
            rf'RECmd.exe -d "{artifacts["Registry"]}" --bn "{batch_file}" --csv "{output_dir}" --csvf "RECmd_Results.csv"',
            recmd_csv
        )
    else:
        print("[❌] RECmd skipped: UserActivity.reb batch file not found.")
else:
    print("[❌] RECmd skipped: Registry artifacts not found.")

# JLECmd Execution
if os.path.isdir(artifacts["JumpLists"]):
    run_tool(
        "JLECmd (AutomaticDestinations)",
        rf'JLECmd.exe -d "{artifacts["JumpLists"]}" --csv "{output_dir}" --csvf "JumpLists_AutomaticDestinations.csv"',
        os.path.join(output_dir, "JumpLists_AutomaticDestinations.csv")
    )
    run_tool(
        "JLECmd (CustomDestinations)",
        rf'JLECmd.exe -d "{artifacts["JumpLists"]}" --csv "{output_dir}" --csvf "JumpLists_CustomDestinations.csv"',
        os.path.join(output_dir, "JumpLists_CustomDestinations.csv")
    )
    combine_jlecmd_outputs()
else:
    print("[❌] JLECmd skipped: Jump List artifacts not found.")

# MFTECmd Execution
if os.path.exists(artifacts["MFT"]):
    mftecmd_csv = os.path.join(output_dir, "MFTECmd_Results.csv")
    run_tool(
        "MFTECmd",
        rf'MFTECmd.exe -f "{artifacts["MFT"]}" --csv "{output_dir}" --csvf "MFTECmd_Results.csv"',
        mftecmd_csv
    )
else:
    print("[❌] MFTECmd skipped: MFT artifact not found.")

# Generate Final Consolidated Report
if results:
    final_df = pd.concat(results, ignore_index=True)
    final_df.to_csv(output_file, index=False)
    print(f"\n✅ Final consolidated report saved to: {output_file}")

    # Generate Summary
    generate_summary()

    # Move individual tool results to Tool_Outputs folder
    for tool_csv in ["RECmd_Results.csv", "JLECmd_Results.csv", "MFTECmd_Results.csv"]:
        source_path = os.path.join(output_dir, tool_csv)
        if os.path.exists(source_path):
            destination_path = os.path.join(tool_outputs_dir, tool_csv)
            os.rename(source_path, destination_path)
            print(f"[✔] Moved {tool_csv} to {tool_outputs_dir}.")
else:
    print("\n⚠ No results generated. All tools failed or artifacts were missing.")
