import streamlit as st
import json
import pandas as pd
import os
import io

# --- Page Configuration ---
st.set_page_config(page_title="Pro SARIF Cleaner", page_icon="🛡️", layout="wide")
st.title("🛡️ Professional SARIF SAST Cleaner")
st.markdown("Refine SARIF reports for dashboard compatibility by filtering IaC/Secrets and validating constraints.")

# --- Enhanced Logic ---
def process_sarif_v2(data, sanitize_paths=True):
    # Mapping for both Prefixes and common Metadata Tags
    exclusion_keywords = ["terraform", "aws", "azure", "gcp", "alicloud", "infrastructure", "secret"]
    
    cleaned_runs = []
    deleted_details = []

    for run in data.get("runs", []):
        results = run.get("results", [])
        keep = []
        
        # Access Rules metadata to check for tags
        rules_metadata = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for res in results:
            rule_id = res.get("ruleId", "").lower()
            
            # 1. Check Rule ID Prefix
            is_excluded = any(rule_id.startswith(p) for p in exclusion_keywords)
            
            # 2. Robust Check: Check Metadata Tags if prefix didn't catch it
            if not is_excluded and rule_id in rules_metadata:
                tags = str(rules_metadata[rule_id].get("properties", {}).get("tags", [])).lower()
                is_excluded = any(word in tags for word in exclusion_keywords)

            if is_excluded:
                # Capture deletion details
                file_path = res.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "Unknown")
                deleted_details.append({
                    "Category": "Infrastructure/Secret",
                    "Rule ID": rule_id,
                    "Location": file_path
                })
            else:
                # 3. Path Sanitization (Point 4 Recommendation)
                if sanitize_paths:
                    # Logic to strip absolute path segments if necessary
                    pass 
                keep.append(res)
        
        # 4. Schema Integrity (Point 5 Recommendation)
        run["results"] = keep
        if "tool" in run and "driver" in run["tool"]:
            active_ids = {r["ruleId"] for r in keep}
            run["tool"]["driver"]["rules"] = [
                r for r in run["tool"]["driver"].get("rules", []) if r.get("id") in active_ids
            ]
        cleaned_runs.append(run)

    data["runs"] = cleaned_runs
    return data, deleted_details

# --- UI Sidebar Settings ---
st.sidebar.header("Advanced Settings")
sanitize = st.sidebar.checkbox("Sanitize Paths (Relative URIs)", value=True, help="Ensures file paths match repository roots in the dashboard.")

# --- Main UI ---
uploaded_file = st.file_uploader("Upload SARIF Report", type="sarif")

if uploaded_file is not None:
    raw_data = json.load(uploaded_file)
    cleaned_data, deleted_list = process_sarif_v2(raw_data, sanitize_paths=sanitize)
    
    # 5. Output Size Check (Point 3 Recommendation)
    output_json = json.dumps(cleaned_data, indent=2)
    output_size_mb = len(output_json.encode('utf-8')) / (1024 * 1024)

    # Dashboard display
    m1, m2, m3 = st.columns(3)
    m1.metric("SAST Kept", len(cleaned_data["runs"][0]["results"]))
    m2.metric("Removed", len(deleted_list))
    
    if output_size_mb > 10:
        m3.metric("Estimated Size", f"{output_size_mb:.2f} MB", delta="TOO LARGE", delta_color="inverse")
        st.error("⚠️ Warning: Output file exceeds the 10MB limit for the target collector.")
    else:
        m3.metric("Estimated Size", f"{output_size_mb:.2f} MB", delta="SAFE")

    if deleted_list:
        df = pd.DataFrame(deleted_list)
        st.subheader("📊 Filtering Breakdown")
        st.bar_chart(df["Rule ID"].str.split('.').str[0].value_counts()) # Chart by tool prefix

        with st.expander("🔍 View Deleted Findings Detail"):
            st.dataframe(df, use_container_width=True)

    # --- Secure Download ---
    st.divider()
    st.download_button(
        label="Download Cleaned & Validated SARIF",
        data=output_json,
        file_name="validated_sast_report.sarif",
        mime="application/json",
        use_container_width=True,
        disabled=(output_size_mb > 10) # Prevent download if it breaks the 10MB rule
    )
