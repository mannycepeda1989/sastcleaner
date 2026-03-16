
import streamlit as st
import json
import io

# --- Page Config ---
st.set_page_config(page_title="SARIF SAST Cleaner", page_icon="🛡️")

st.title("🛡️ SARIF SAST Cleaner")
st.markdown("""
Upload a SARIF file to filter out **IaC** and **Secret** findings, leaving only **SAST/Code Weaknesses**.
""")

# --- Filter Logic ---
def filter_sarif(json_data):
    excluded_prefixes = ["terraform.", "aws-", "azure-", "gcp-", "alicloud.", "yaml.openapi.security.s3"]
    
    for run in json_data.get("runs", []):
        results = run.get("results", [])
        filtered_results = [
            res for res in results
            if not any(res.get("ruleId", "").startswith(prefix) for prefix in excluded_prefixes)        ]
        run["results"] = filtered_results
        
        # Clean up rules metadata
        active_rule_ids = {res["ruleId"] for res in filtered_results}
        if "tool" in run and "driver" in run["tool"]:
            rules = run["tool"]["driver"].get("rules", [])
            run["tool"]["driver"]["rules"] = [
                rule for rule in rules if rule.get("id") in active_rule_ids
            ]
    return json_data

# --- File Uploader ---
uploaded_file = st.file_uploader("Choose a SARIF file", type="sarif")

if uploaded_file is not None:
    # Read the file
    raw_data = json.load(uploaded_file)
    
    # Process the file
    with st.spinner('Cleaning report...'):
        cleaned_data = filter_sarif(raw_data)
        
    # Convert back to string for download
    output_json = json.dumps(cleaned_data, indent=2)
    
    st.success(f"Cleanup complete! Remaining findings: {len(cleaned_data['runs'][0]['results'])}")
    
    # Download Button
    st.download_button(
        label="Download Cleaned SARIF",
        data=output_json,
        file_name="cleaned_report.sarif",
        mime="application/json"
    )
