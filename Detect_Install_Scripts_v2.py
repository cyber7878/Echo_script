import argparse, json, re
import requests
from packaging.version import parse as vparse

NPM = "https://registry.npmjs.org"
INSTALL_KEYS = {"preinstall", "install", "postinstall", "prepare"}

# Suspicious patterns grouped by reason/category.
# Each category contains regex patterns that we search for inside install scripts.
PATTERNS = {
    "encoded_execution": [r"base64\s+(-d|--decode)", r"atob\s*\(", r"Buffer\.from\(.*base64", r"eval\s*\(", r"Function\s*\("],
    "download_execute": [r"curl\s+.*\|\s*(sh|bash|node|python)", r"wget\s+.*\|\s*(sh|bash|node|python)", r"powershell", r"Invoke-WebRequest"],
    "shell_execution": [r"child_process", r"execSync\s*\(", r"exec\s*\(", r"spawn\s*\("],
    "credential_access": [r"process\.env", r"\.npmrc", r"NPM_TOKEN", r"GITHUB_TOKEN", r"AWS_ACCESS_KEY"],
    "network": [r"https?://", r"fetch\s*\(", r"axios\.", r"https?\.request"],
}


def script_reasons(script):
    """
    Receives one install script as a string.
    Returns a list of suspicious categories found in that script.
    """
    
    reasons = []
    for name, pats in PATTERNS.items():
        
        # Check if any pattern from this category appears in the script.
        if any(re.search(p, script, re.I) for p in pats):
            reasons.append(name)
    return reasons

def install_scripts(meta):
    """
    Receives metadata for one npm package version.
    Extracts only install scripts
    """
    scripts = meta.get("scripts") or {}
    
    # Return only scripts whose key is one of INSTALL_KEYS
    return {k: v for k, v in scripts.items() if k in INSTALL_KEYS and isinstance(v, str)}

def analyze(pkg):
    """
    Analyzes one npm package across all its published versions.
    Looks for suspicious install-time behavior.
    """
    
    # Download package metadata from npm registry.
    data = requests.get(f"{NPM}/{pkg}", timeout=20).json()

    # Get all versions from the metadata and sort them by real version order.
    versions = sorted(data.get("versions", {}).items(), key=lambda x: vparse(x[0]))

    had_install_before = False
    seen_versions_before = False
    results = []

    # Go over every version in chronological version order.
    for ver, meta in versions:
        scripts = install_scripts(meta)
        reasons = []

        # Check for packages that had versions without install scripts
        # And this Version is With install scripts
        if scripts and not had_install_before and not had_install_before:
            reasons.append("install_script_introduced_after_clean_history")

        # Check the content of every install script.
        for name, value in scripts.items():
            for r in script_reasons(value):
                reasons.append(f"{name}:{r}")

        # If it had an install script, change the bool
        if scripts:
            had_install_before = True
        seen_versions_before = True

        # If this version has at least one reason, parse it
        if reasons:
            results.append({
                "version": ver,
                "scripts": scripts,
                "reasons": sorted(set(reasons))
            })

    # Return the final report for this package
    return {
        "package": pkg,
        "verdict": "suspicious" if results else "legitimate",
        "versions_checked": len(versions),
        "flagged_versions": results
    }

def main():
    """
    Entry point of the command-line tool.
    Reads package names from the user, analyzes them, and prints JSON output.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("packages", nargs="+")
    args = ap.parse_args()

    reports = []
    for pkg in args.packages:
        try:
            reports.append(analyze(pkg))
        except Exception as e:
            reports.append({"package": pkg, "error": str(e)})

    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
