import streamlit as st
import json
import pandas as pd

# --- Page Configuration ---
st.set_page_config(page_title="SARIF Cleaner", page_icon="🧹")
st.title("🧹 SARIF SAST Cleaner")
st.markdown("Filter out **IaC** and **Secrets** to prepare your SARIF file for AppSec dashboard ingestion.")

# --- Logic ---
def process_sarif(data):
    # Mapping prefixes to categories for the chart
    category_map = {
        "terraform.": "Infrastructure (IaC)",
        "alicloud.": "Infrastructure (IaC)",
        "aws-": "Secrets/Cloud Config",
        "azure-": "Secrets/Cloud Config",
        "gcp-": "Secrets/Cloud Config"
    }
    
    cleaned_runs = []
    deleted_details = []

    for run in data.get("runs", []):
        results = run.get("results", [])
        keep = []
        
        for res in results:
            rule_id = res.get("ruleId", "")
            found_category = next((cat for pref, cat in category_map.items() if rule_id.startswith(pref)), None)
            
            if found_category:
                file_path = res.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "Unknown")
                deleted_details.append({
                    "Category": found_category,
                    "Rule ID": rule_id,
                    "Location": file_path
                })
            else:
                keep.append(res)
        
        run["results"] = keep
        cleaned_runs.append(run)

    data["runs"] = cleaned_runs
    return data, deleted_details

# --- UI ---
uploaded_file = st.file_uploader("Choose a .sarif file", type="sarif")

if uploaded_file is not None:
    raw_data = json.load(uploaded_file)
    cleaned_data, deleted_list = process_sarif(raw_data)
    
    # 1. Metrics
    col1, col2 = st.columns(2)
    col1.metric("SAST Findings Kept", len(cleaned_data["runs"][0]["results"]))
    col2.metric("Non-SAST Removed", len(deleted_list))

    if deleted_list:
        df = pd.DataFrame(deleted_list)

        # 2. Summary Chart
        st.subheader("📊 Removal Summary")
        chart_data = df["Category"].value_counts()
        st.bar_chart(chart_data)

        # 3. Preview Table
        with st.expander("🔍 View Detailed List of Removed Items"):
            st.dataframe(df, use_container_width=True)
    else:
        st.info("No non-SAST findings detected.")

    # 4. Download
    st.divider()
    output_json = json.dumps(cleaned_data, indent=2)
    st.download_button(
        label="Download Cleaned SARIF",
        data=output_json,
        file_name="cleaned_report.sarif",
        mime="application/json",
        use_container_width=True
    )
