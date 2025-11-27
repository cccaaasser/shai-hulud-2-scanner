import os
import json
import sys
import urllib.request
import ssl
import csv
import io

# URL to the Wiz Research CSV file
CSV_URL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

def get_bad_packages_from_csv():
    """
    Fetches and parses the CSV file from Wiz Research.
    Returns a dictionary: { 'package_name': set(['version1', 'version2', ...]) }
    If the version set is empty, it means ALL versions are considered affected.
    """
    print("Fetching malicious package database from Wiz Research...")
    bad_packages = {}
    
    try:
        # Create unverified context for compatibility
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(CSV_URL, context=context, timeout=10) as response:
            content = response.read().decode('utf-8')
            
        reader = csv.reader(io.StringIO(content))
        header = next(reader, None) # Skip header (Package, Version)
        
        count = 0
        for row in reader:
            if not row or len(row) < 1:
                continue
            
            pkg_name = row[0].strip()
            raw_versions = row[1].strip() if len(row) > 1 else ""
            
            versions = set()
            if raw_versions:
                # Format is like: = 1.0.0 || = 1.0.1
                parts = raw_versions.split('||')
                for part in parts:
                    # Clean up string: remove '=', spaces
                    v = part.replace('=', '').strip()
                    if v:
                        versions.add(v)
            
            # If versions is empty, it implies all versions or unknown (flag all)
            bad_packages[pkg_name] = versions
            count += 1
            
        print(f"Successfully loaded {count} package rules.")
        return bad_packages

    except Exception as e:
        print(f"Error fetching or parsing CSV: {e}")
        sys.exit(1)

def check_version_match(pkg_name, installed_version, bad_versions):
    """
    Checks if the installed version matches the list of bad versions.
    """
    # If bad_versions set is empty, we assume ALL versions are bad/suspicious
    if not bad_versions:
        return True
    
    # Exact match check
    if installed_version in bad_versions:
        return True
    
    return False

def scan_directory(root_dir, bad_packages_db):
    print(f"\nScanning directory: {root_dir}")
    print("This may take a while depending on the size of your projects...\n")
    
    found_issues = []
    scanned_files = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Optimization: skip node_modules to avoid scanning every single internal package.json
        # We rely on the top-level package-lock.json for accurate dependency trees.
        if 'node_modules' in dirnames:
            dirnames.remove('node_modules')
        
        # --- Check package-lock.json (Best for specific versions) ---
        if 'package-lock.json' in filenames:
            scanned_files += 1
            lock_path = os.path.join(dirpath, 'package-lock.json')
            try:
                with open(lock_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lock_data = json.load(f)
                
                # Helper to check dependencies dictionary
                def check_deps_dict(deps, path_prefix=""):
                    if not isinstance(deps, dict):
                        return
                        
                    for pkg, info in deps.items():
                        # Handle lockfile v2/v3 "packages" format where key is "node_modules/pkg"
                        clean_pkg_name = pkg.split('node_modules/')[-1]
                        
                        if clean_pkg_name in bad_packages_db:
                            installed_ver = info.get('version', 'unknown')
                            affected_versions = bad_packages_db[clean_pkg_name]
                            
                            if check_version_match(clean_pkg_name, installed_ver, affected_versions):
                                found_issues.append({
                                    'file': lock_path,
                                    'package': clean_pkg_name,
                                    'version': installed_ver,
                                    'affected_versions': list(affected_versions) if affected_versions else "ALL",
                                    'type': 'Lockfile (Installed)'
                                })
                        
                        # Recurse if dependencies are nested (Lockfile v1)
                        if 'dependencies' in info:
                            check_deps_dict(info['dependencies'])

                # Check 'dependencies' (Lockfile v1)
                if 'dependencies' in lock_data:
                    check_deps_dict(lock_data['dependencies'])
                
                # Check 'packages' (Lockfile v2/v3)
                if 'packages' in lock_data:
                    check_deps_dict(lock_data['packages'])

            except Exception as e:
                # print(f"Could not parse {lock_path}: {e}")
                pass

        # --- Check package.json (Direct definitions) ---
        if 'package.json' in filenames:
            scanned_files += 1
            pkg_path = os.path.join(dirpath, 'package.json')
            try:
                with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                    pkg_data = json.load(f)
                
                sections = ['dependencies', 'devDependencies', 'peerDependencies']
                for section in sections:
                    if section in pkg_data:
                        for dep_name, dep_range in pkg_data[section].items():
                            if dep_name in bad_packages_db:
                                # In package.json, we only have a range (e.g. ^1.0.0), not the exact installed version.
                                # We warn the user to check their lockfile.
                                found_issues.append({
                                    'file': pkg_path,
                                    'package': dep_name,
                                    'version': dep_range,
                                    'affected_versions': "Check Lockfile",
                                    'type': f'Manifest ({section})'
                                })
            except Exception:
                pass

    return found_issues, scanned_files

def main():
    print("--- Shai-Hulud v2 NPM Scanner ---")
    print(f"Database Source: {CSV_URL}\n")
    
    # 1. Load Database
    bad_packages_db = get_bad_packages_from_csv()
    
    # 2. Get arguments
    if len(sys.argv) > 1:
        start_dir = sys.argv[1]
    else:
        start_dir = os.getcwd()
        print(f"No path provided. Scanning current directory: {start_dir}")
        print("Usage: python scan_shai_hulud_v2.py <path_to_scan>")

    # 3. Scan
    issues, count = scan_directory(start_dir, bad_packages_db)
    
    # 4. Report
    print(f"\nScan complete. Parsed {count} package files.")
    
    if not issues:
        print("\n✅ CLEAN: No compromised packages found in the scanned path.")
    else:
        print(f"\n🚨 ALERT: Found {len(issues)} potential matches!\n")
        print(f"{'PACKAGE':<40} | {'VERSION':<15} | {'LOCATION'}")
        print("-" * 100)
        for issue in issues:
            print(f"{issue['package']:<40} | {issue['version']:<15} | {issue['file']}")
            if issue['affected_versions'] != "Check Lockfile":
                 print(f"   └── Vulnerable versions: {issue['affected_versions']}")
        print("-" * 100)
        print("\nPlease verify the identified packages manually.")
        print("If a match is in package.json, ensure the installed version in package-lock.json is safe.")

if __name__ == "__main__":
    main()
