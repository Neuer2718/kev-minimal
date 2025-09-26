import argparse
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

def load_kev(path_or_url: str | None) -> pd.DataFrame:
    candidates = []
    if path_or_url:
        candidates.append(path_or_url)
    candidates += [CISA_KEV_URL, "sample_kev.csv"]
    last_err = None
    for src in candidates:
        try:
            df = pd.read_csv(src, low_memory=False)
            if "dateAdded" in df.columns:
                df["dateAdded"] = pd.to_datetime(df["dateAdded"], errors="coerce")
            return df
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Failed to load KEV from any source. Last error: {last_err}")

def basic_stats(df: pd.DataFrame) -> dict:
    col_vendor = "vendorProject" if "vendorProject" in df.columns else None
    years = df["dateAdded"].dt.year.dropna().astype(int) if "dateAdded" in df.columns else pd.Series(dtype=int)
    stats = {
        "n_rows": len(df),
        "n_unique_vendors": df[col_vendor].nunique() if col_vendor else None,
        "first_year": int(years.min()) if len(years) else None,
        "latest_year": int(years.max()) if len(years) else None,
    }
    return stats

def plot_top_vendors(df: pd.DataFrame, out_png: str, k: int = 10):
    if "vendorProject" not in df.columns: 
        return
    vc = df["vendorProject"].value_counts().head(k)
    Path(out_png).parent.mkdir(parents=True, exist_ok=True)
    plt.figure()
    vc.plot(kind="bar")
    plt.title(f"Top {k} Vendors in CISA KEV")
    plt.xlabel("Vendor")
    plt.ylabel("Vulnerability Count")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

def plot_monthly_trend(df: pd.DataFrame, out_png: str):
    if "dateAdded" not in df.columns:
        return
    s = pd.to_datetime(df["dateAdded"], errors="coerce").dt.to_period("M").dt.to_timestamp()
    counts = s.value_counts().sort_index()
    Path(out_png).parent.mkdir(parents=True, exist_ok=True)
    plt.figure()
    counts.plot(kind="line", marker="o")
    plt.title("CISA KEV: Vulnerabilities Added per Month")
    plt.xlabel("Month")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

def main():
    ap = argparse.ArgumentParser(description="Analyze CISA Known Exploited Vulnerabilities")
    ap.add_argument("--input", help="CSV path (optional). If omitted, tries CISA URL, then sample_kev.csv")
    ap.add_argument("--outdir", default="out", help="Output directory for PNGs")
    args = ap.parse_args()

    df = load_kev(args.input)
    stats = basic_stats(df)
    print("Rows:", stats["n_rows"])
    if stats["n_unique_vendors"] is not None:
        print("Unique vendors:", stats["n_unique_vendors"])
    if stats["first_year"] and stats["latest_year"]:
        print(f"Range of years in KEV: {stats['first_year']}–{stats['latest_year']}")

    plot_top_vendors(df, f"{args.outdir}/top_vendors.png", k=10)
    plot_monthly_trend(df, f"{args.outdir}/monthly_trend.png")
    print(f"Wrote: {args.outdir}/top_vendors.png and {args.outdir}/monthly_trend.png")

if __name__ == "__main__":
    main()
