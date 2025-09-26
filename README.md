# KEV Minimal: CISA Known Exploited Vulnerabilities Analysis

This is a minimal but practical project that analyzes the [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).  
The KEV catalog lists CVEs that are actively exploited in the wild and prioritized by U.S. federal agencies.

## Why this matters
Organizations like the **FBI**, **NSA**, and **CISA** all use KEV data to drive cyber defense and vulnerability management.  
Being able to parse, filter, and visualize this data is directly relevant to real-world government cyber operations.

## Features
- **Data ingestion**: Pulls KEV CSV directly from CISA (falls back to local sample file if offline).
- **Summary stats**: Total vulnerabilities, unique vendors, date ranges.
- **Visualizations**:
  - Top affected vendors (`out/top_vendors.png`)
  - Monthly trend of newly added exploited vulnerabilities (`out/monthly_trend.png`)

## Usage
1. Create a virtual environment and install requirements:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
