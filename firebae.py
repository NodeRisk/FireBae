#!/usr/bin/env python3
"""
FireBae - Firebase Misconfiguration Security Scanner
Created by NodeRisk - V1.0

Comprehensive Firebase misconfiguration checker (read-first, optional gated writes).
- Read checks: RealtimeDB read, Firestore list, Storage listing, Hosting probe, Functions probe
- Optional write checks (only if --confirm-write is provided): Storage upload (with folder support),
  RealtimeDB write/delete, Firestore doc create/delete.
- Produces human-readable console output and optional JSON/CSV report.
- Can extract targets from Firebase config files or configuration snippets

USAGE (read-only with manual targets):
    python firebase_misconfig_tool.py --targets example other-project

USAGE (extract targets from Firebase config):
    python firebase_misconfig_tool.py --config-file firebase-config.json
    python firebase_misconfig_tool.py --config-text '{"projectId":"exmaple","databaseURL":"https://exmaple.firebaseio.com"}'

USAGE (with writes, DANGEROUS - only with authorization):
    python firebase_misconfig_tool.py --targets target1 \
      --confirm-write --upload-file ./noderisk.html --upload-name "proof.html" --upload-folder "pentest_tests"

USAGE (from discovered API endpoints or config snippets):
    # When you find: /v1alpha/projects/-/apps/1:45155135:web:example123/webConfig
    # Or Firebase config with projectId, databaseURL, storageBucket, etc.
    python firebase_misconfig_tool.py --config-text 'paste-your-config-here'

Dependencies:
    pip install requests

WARNING: Only run write-enabled actions against targets you own or have explicit written permission to test.
"""
import argparse
import requests
import time
import json
import csv
import os
import mimetypes
from datetime import datetime
from typing import List, Dict, Any

UA = {"User-Agent": "firebase-misconfig-tool/1.0"}
TIMEOUT = 10
SLEEP = 0.4

# Helper utils
def safe_get(url, headers=None, params=None):
    try:
        r = requests.get(url, headers=headers or UA, params=params, timeout=TIMEOUT)
        return r.status_code, r.headers, r.text
    except Exception as e:
        return None, None, f"error: {e}"

def safe_post(url, data=None, headers=None, params=None, files=None):
    try:
        r = requests.post(url, data=data, headers=headers or UA, params=params, files=files, timeout=TIMEOUT)
        return r.status_code, r.headers, r.text
    except Exception as e:
        return None, None, f"error: {e}"

def safe_put(url, data=None, headers=None, params=None):
    try:
        r = requests.put(url, data=data, headers=headers or UA, params=params, timeout=TIMEOUT)
        return r.status_code, r.headers, r.text
    except Exception as e:
        return None, None, f"error: {e}"

def safe_delete(url, headers=None, params=None):
    try:
        r = requests.delete(url, headers=headers or UA, params=params, timeout=TIMEOUT)
        return r.status_code, r.headers, r.text
    except Exception as e:
        return None, None, f"error: {e}"

# Guess bucket names from a project identifier or storageBucket string
def guess_buckets(project_or_bucket: str) -> List[str]:
    guesses = []
    p = project_or_bucket
    if p.endswith(".appspot.com") or p.endswith(".firebasestorage.app"):
        guesses.append(p)
    guesses.extend([
        f"{p}.appspot.com",
        f"{p}.firebasestorage.app",
        f"{p}.storage.googleapis.com",
        p
    ])
    # de-dup preserving order
    seen=set()
    out=[]
    for g in guesses:
        if g not in seen:
            seen.add(g); out.append(g)
    return out

# Checks
def check_realtime_read(target: str) -> Dict[str, Any]:
    urls = [
        f"https://{target}.firebaseio.com/.json",
        f"https://{target}.firebasedatabase.app/.json",
        f"https://{target}/.json"  # in case they pass full URL-ish
    ]
    results = []
    for u in urls:
        st, hdr, body = safe_get(u)
        results.append({"url":u, "status":st, "snippet": (body[:1000] if isinstance(body,str) else str(body))})
        time.sleep(SLEEP)
    return {"realtime": results}

def check_realtime_write_test(target: str, test_node="noderisk_pentest_probe", test_value="pentest-ok") -> Dict[str, Any]:
    # Try PUT to create a node, then DELETE
    base = f"https://{target}.firebaseio.com"
    urls = [
        f"{base}/{test_node}.json",
        f"https://{target}.firebasedatabase.app/{test_node}.json"
    ]
    results=[]
    for u in urls:
        put_status, _, put_body = safe_put(u, data=json.dumps(test_value), headers={"Content-Type":"application/json"})
        # verify by GET
        get_status, _, get_body = safe_get(u)
        del_status, _, del_body = safe_delete(u)
        results.append({
            "url":u,
            "put_status":put_status,
            "put_body_snippet": (str(put_body)[:500] if put_body else ""),
            "get_status": get_status,
            "get_body_snippet": (str(get_body)[:500] if get_body else ""),
            "delete_status": del_status,
        })
        time.sleep(SLEEP)
    return {"realtime_write": results}

def check_firestore_read(project: str) -> Dict[str, Any]:
    # list documents (pageSize=1)
    url = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents?pageSize=1"
    st, hdr, body = safe_get(url)
    return {"url": url, "status": st, "snippet": (body[:1000] if isinstance(body,str) else str(body))}

def check_firestore_write_test(project: str, collection="pentest_probes", doc_id=None, payload=None) -> Dict[str, Any]:
    # Construct a create doc call:
    # POST https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/{collectionId}
    # body: { "fields": { "probe" : {"stringValue":"ok"} } }
    if not payload:
        payload = {"probe": {"stringValue": "pentest-ok"}, "time": {"stringValue": str(datetime.utcnow())}}
    url = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/{collection}"
    st, hdr, body = safe_post(url, data=json.dumps(payload), headers={"Content-Type":"application/json"})
    # If created, try to parse name to delete it
    del_result = None
    if st == 200 or st == 201:
        try:
            resp = json.loads(body)
            name = resp.get("name")  # full resource path
            # Delete
            if name:
                del_url = f"https://firestore.googleapis.com/v1/{name}"
                d_st, d_hdr, d_body = safe_delete(del_url)
                del_result = {"delete_status": d_st, "delete_snippet": (d_body[:500] if isinstance(d_body,str) else str(d_body))}
        except Exception as e:
            del_result = {"error_parsing": str(e)}
    return {"create_status": st, "create_snippet": (body[:1000] if isinstance(body,str) else str(body)), "delete": del_result}

def check_storage_list(bucket: str) -> Dict[str,Any]:
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o"
    st, hdr, body = safe_get(url)
    # quick indicator if listing present
    listable = False
    if isinstance(body, str) and '"items"' in body:
        listable = True
    return {"url":url, "status":st, "listable": listable, "snippet": (body[:1000] if isinstance(body,str) else str(body))}

def storage_upload(bucket: str, file_path: str, upload_name: str) -> Dict[str,Any]:
    # Upload using Firebase GCS upload endpoint
    # POST https://firebasestorage.googleapis.com/v0/b/{bucket}/o?uploadType=media&name={object}
    if not os.path.isfile(file_path):
        return {"error": "file_not_found", "file_path": file_path}
    mimetype = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
    url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
    params = {"uploadType":"media", "name": upload_name}
    with open(file_path, "rb") as f:
        data = f.read()
    headers = {"Content-Type": mimetype, **UA}
    st, hdr, body = safe_post(url, data=data, headers=headers, params=params)
    return {"url": url, "params": params, "status": st, "response_snippet": (body[:1000] if isinstance(body,str) else str(body))}

def storage_delete(bucket: str, object_name: str) -> Dict[str,Any]:
    # DELETE https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{object}?alt=media  (object must be URL-encoded)
    from urllib.parse import quote
    obj = quote(object_name, safe='')
    url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{obj}"
    st, hdr, body = safe_delete(url)
    return {"url": url, "status": st, "snippet": (body[:500] if isinstance(body,str) else str(body))}

def check_hosting(domain: str) -> Dict[str,Any]:
    urls = [f"https://{domain}.web.app/", f"https://{domain}.firebaseapp.com/", f"https://{domain}/"]
    results=[]
    for u in urls:
        st, hdr, body = safe_get(u)
        contains_config = False
        if isinstance(body, str) and ("apiKey" in body or "firebaseConfig" in body or "projectId" in body):
            contains_config = True
        results.append({"url":u, "status": st, "config_like": contains_config, "snippet": (body[:800] if isinstance(body,str) else str(body))})
        time.sleep(SLEEP)
    return {"hosting": results}

def check_cloud_functions(project: str, regions=None):
    if not regions:
        regions = ["us-central1", "us-east1", "europe-west1", "asia-south1"]
    results=[]
    for r in regions:
        url = f"https://{r}-{project}.cloudfunctions.net/"
        st, hdr, body = safe_get(url)
        results.append({"url":url, "status":st, "snippet": (body[:500] if isinstance(body,str) else str(body))})
        time.sleep(SLEEP)
    return {"functions": results}

def check_firebase_config_endpoints(project: str) -> Dict[str, Any]:
    """Check for exposed Firebase configuration endpoints that might leak info."""
    endpoints = [
        f"https://firebase.googleapis.com/v1alpha/projects/{project}/webApps",
        f"https://firebase.googleapis.com/v1alpha/projects/{project}/iosApps", 
        f"https://firebase.googleapis.com/v1alpha/projects/{project}/androidApps",
        f"https://{project}.firebaseapp.com/__/firebase/init.js",
        f"https://{project}.web.app/__/firebase/init.js",
        f"https://{project}.firebaseapp.com/__/firebase/init.json",
        f"https://{project}.web.app/__/firebase/init.json"
    ]
    
    results = []
    for url in endpoints:
        st, hdr, body = safe_get(url)
        has_config = False
        if isinstance(body, str) and any(key in body for key in ["apiKey", "projectId", "appId", "config"]):
            has_config = True
        results.append({
            "url": url,
            "status": st,
            "has_config_data": has_config,
            "snippet": (body[:800] if isinstance(body, str) else str(body))
        })
        time.sleep(SLEEP)
    
    return {"config_endpoints": results}

# Runner that bundles checks per target
def run_checks(target: str, do_write=False, upload_file=None, upload_name=None, upload_folder=None, cleanup=False) -> Dict[str,Any]:
    out = {"target": target, "timestamp": datetime.utcnow().isoformat()+"Z", "checks": {}}
    # Realtime read
    out["checks"].update(check_realtime_read(target))
    # Firestore read
    out["checks"]["firestore"] = check_firestore_read(target)
    # Storage guesses
    bucket_guesses = guess_buckets(target)
    storage_results = []
    for b in bucket_guesses:
        res = check_storage_list(b)
        res["bucket_guess"] = b
        storage_results.append(res)
        time.sleep(SLEEP)
    out["checks"]["storage_guesses"] = storage_results
    # Hosting
    out["checks"].update(check_hosting(target))
    # Cloud Functions
    out["checks"].update(check_cloud_functions(target))
    # Firebase Config Endpoints
    out["checks"].update(check_firebase_config_endpoints(target))
    # Firestore write test (optional)
    if do_write:
        out["checks"]["realtime_write_test"] = check_realtime_write_test(target)
        # Firestore write test:
        out["checks"]["firestore_write_test"] = check_firestore_write_test(target)
        # Storage upload: only do if upload_file provided
        if upload_file and upload_name:
            upload_results=[]
            for b in bucket_guesses:
                # construct name with folder if provided
                name = f"{upload_folder.rstrip('/')}/{upload_name}" if upload_folder else upload_name
                r = storage_upload(b, upload_file, name)
                r["bucket_attempt"] = b
                upload_results.append(r)
                time.sleep(SLEEP)
            out["checks"]["storage_upload_results"] = upload_results
            # Optional cleanup: attempt delete for created object
            if cleanup:
                deletes=[]
                for r in upload_results:
                    if r.get("status") in (200,201):
                        # attempt delete
                        b = r.get("bucket_attempt")
                        name = r["params"]["name"] if "params" in r and r["params"].get("name") else upload_name
                        d = storage_delete(b, name)
                        d["bucket"] = b
                        deletes.append(d)
                        time.sleep(SLEEP)
                out["checks"]["storage_delete_attempts"] = deletes
    return out

def write_report_json(report, outpath):
    with open(outpath, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved to {outpath}")

def write_report_csv(report, outpath):
    # Flatten lightweight: each target per row with key summary
    rows=[]
    for item in report:
        target = item.get("target")
        ts = item.get("timestamp")
        # quick summary counts
        realtime_public = any(r.get("status")==200 for r in item["checks"].get("realtime",[]))
        firestore_ok = (item["checks"].get("firestore",{}).get("status") == 200)
        storage_listable = any(r.get("listable") for r in item["checks"].get("storage_guesses",[]))
        rows.append({"target":target,"timestamp":ts,"realtime_read_200":realtime_public,"firestore_read_200":firestore_ok,"storage_listable":storage_listable})
    keys = rows[0].keys() if rows else ["target","timestamp"]
    with open(outpath,"w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(keys))
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"[+] CSV summary saved to {outpath}")

def print_findings_summary(all_reports, write_enabled=False):
    """Print a consolidated summary of all findings across targets."""
    print("\n" + "="*80)
    print("🔍 SCAN RESULTS SUMMARY")
    print("="*80)
    
    total_targets = len(all_reports)
    findings = {
        'realtime_readable': [],
        'firestore_readable': [],
        'storage_listable': [],
        'config_exposed': [],
        'hosting_live': [],
        'functions_accessible': []
    }
    
    if write_enabled:
        findings.update({
            'realtime_writable': [],
            'firestore_writable': [],
            'storage_writable': []
        })
    
    # Analyze each target
    for report in all_reports:
        target = report.get('target', 'unknown')
        checks = report.get('checks', {})
        
        # Check Realtime Database
        realtime_checks = checks.get('realtime', [])
        for r in realtime_checks:
            if r.get('status') == 200:
                findings['realtime_readable'].append(f"{target} -> {r['url']}")
        
        # Check Firestore
        firestore = checks.get('firestore', {})
        if firestore.get('status') == 200:
            findings['firestore_readable'].append(f"{target} -> {firestore['url']}")
        
        # Check Storage
        storage_checks = checks.get('storage_guesses', [])
        for s in storage_checks:
            if s.get('listable'):
                findings['storage_listable'].append(f"{target} -> {s['bucket_guess']}")
        
        # Check Config endpoints
        config_checks = checks.get('config_endpoints', [])
        for c in config_checks:
            if c.get('has_config_data'):
                findings['config_exposed'].append(f"{target} -> {c['url']}")
        
        # Check Hosting
        hosting_checks = checks.get('hosting', [])
        for h in hosting_checks:
            if h.get('status') == 200 and h.get('config_like'):
                findings['hosting_live'].append(f"{target} -> {h['url']}")
        
        # Check Functions
        functions_checks = checks.get('functions', [])
        for f in functions_checks:
            if f.get('status') == 200:
                findings['functions_accessible'].append(f"{target} -> {f['url']}")
        
        # Write test results (if enabled)
        if write_enabled:
            realtime_write = checks.get('realtime_write_test', {}).get('realtime_write', [])
            for rw in realtime_write:
                if rw.get('put_status') == 200:
                    findings['realtime_writable'].append(f"{target} -> {rw['url']}")
            
            firestore_write = checks.get('firestore_write_test', {})
            if firestore_write.get('create_status') in [200, 201]:
                findings['firestore_writable'].append(f"{target} -> Firestore write successful")
            
            storage_uploads = checks.get('storage_upload_results', [])
            for su in storage_uploads:
                if su.get('status') in [200, 201]:
                    findings['storage_writable'].append(f"{target} -> {su['bucket_attempt']}")
    
    # Print findings
    print(f"📊 Scanned {total_targets} target(s)")
    print()
    
    # Critical findings (red flags)
    critical_count = 0
    
    if findings['realtime_readable']:
        print("🚨 CRITICAL: Realtime Database Public Read Access")
        for item in findings['realtime_readable']:
            print(f"   ⚠️  {item}")
        critical_count += len(findings['realtime_readable'])
        print()
    
    if findings['firestore_readable']:
        print("🚨 CRITICAL: Firestore Public Read Access")
        for item in findings['firestore_readable']:
            print(f"   ⚠️  {item}")
        critical_count += len(findings['firestore_readable'])
        print()
    
    if findings['storage_listable']:
        print("🚨 CRITICAL: Storage Bucket Public Listing")
        for item in findings['storage_listable']:
            print(f"   ⚠️  {item}")
        critical_count += len(findings['storage_listable'])
        print()
    
    # High severity findings
    high_count = 0
    
    if findings['config_exposed']:
        print("⚠️  HIGH: Firebase Configuration Exposed")
        for item in findings['config_exposed']:
            print(f"   📄 {item}")
        high_count += len(findings['config_exposed'])
        print()
    
    # Write test results
    if write_enabled:
        write_count = 0
        
        if findings['realtime_writable']:
            print("🔥 CRITICAL: Realtime Database Write Access")
            for item in findings['realtime_writable']:
                print(f"   ✍️  {item}")
            write_count += len(findings['realtime_writable'])
            print()
        
        if findings['firestore_writable']:
            print("🔥 CRITICAL: Firestore Write Access")
            for item in findings['firestore_writable']:
                print(f"   ✍️  {item}")
            write_count += len(findings['firestore_writable'])
            print()
        
        if findings['storage_writable']:
            print("🔥 CRITICAL: Storage Bucket Write Access")
            for item in findings['storage_writable']:
                print(f"   ✍️  {item}")
            write_count += len(findings['storage_writable'])
            print()
        
        if write_count > 0:
            critical_count += write_count
    
    # Informational findings
    info_count = 0
    
    if findings['hosting_live']:
        print("ℹ️  INFO: Live Hosting Sites")
        for item in findings['hosting_live']:
            print(f"   🌐 {item}")
        info_count += len(findings['hosting_live'])
        print()
    
    if findings['functions_accessible']:
        print("ℹ️  INFO: Accessible Cloud Functions")
        for item in findings['functions_accessible']:
            print(f"   ⚡ {item}")
        info_count += len(findings['functions_accessible'])
        print()
    
    # Overall summary
    print("-" * 80)
    if critical_count > 0:
        print(f"🚨 SECURITY ISSUES FOUND: {critical_count} critical finding(s)")
    elif high_count > 0:
        print(f"⚠️  POTENTIAL ISSUES: {high_count} high severity finding(s)")
    elif info_count > 0:
        print(f"ℹ️  INFORMATIONAL: {info_count} item(s) of interest")
    else:
        print("✅ No major security issues detected")
    
    if critical_count > 0:
        print("   🔧 Recommendation: Review Firebase security rules immediately")
    
    print("="*80)

def extract_firebase_info_from_config(config_text: str) -> List[str]:
    """Extract Firebase project identifiers from configuration text/JSON."""
    import re
    targets = []
    
    # Extract projectId from JSON-like configs
    project_matches = re.findall(r'"projectId"\s*:\s*"([^"]+)"', config_text)
    targets.extend(project_matches)
    
    # Extract from databaseURL
    db_matches = re.findall(r'"databaseURL"\s*:\s*"https://([^."]+)', config_text)
    targets.extend(db_matches)
    
    # Extract from storageBucket
    storage_matches = re.findall(r'"storageBucket"\s*:\s*"([^"]+)"', config_text)
    targets.extend(storage_matches)
    
    # Extract from authDomain
    auth_matches = re.findall(r'"authDomain"\s*:\s*"([^."]+)', config_text)
    targets.extend(auth_matches)
    
    # Extract from Firebase API endpoints like /v1alpha/projects/-/apps/...
    api_matches = re.findall(r'/v1alpha/projects/([^/]+)/apps/', config_text)
    targets.extend([m for m in api_matches if m != '-'])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    
    return unique_targets

def print_banner():
    """Print the FireBae ASCII art banner."""
    banner = """
▄████  ▄█ █▄▄▄▄ ▄███▄   ███   ██   ▄███▄   
█▀   ▀ ██ █  ▄▀ █▀   ▀  █  █  █ █  █▀   ▀  
█▀▀    ██ █▀▀▌  ██▄▄    █ ▀ ▄ █▄▄█ ██▄▄    
█      ▐█ █  █  █▄   ▄▀ █  ▄▀ █  █ █▄   ▄▀ 
 █      ▐   █   ▀███▀   ███      █ ▀███▀   
  ▀        ▀                    █          
                               ▀           
    """
    print(banner)
    print("🔥 FireBae by NodeRisk - V1.0")
    print("⚠️  Only for educational purposes and authorized pentest engagements only")
    print("📋 Use responsibly - Test only systems you own or have explicit permission")
    print("="*80)

def main():
    print_banner()
    p = argparse.ArgumentParser(
        description="🔥 FireBae - Firebase Misconfiguration Scanner by NodeRisk\n⚠️ Educational & Authorized Testing Only",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--targets","-t", nargs="+", help="Project IDs / candidate hostnames / bucket names")
    p.add_argument("--config-file", help="Extract targets from Firebase config file (JSON)")
    p.add_argument("--config-text", help="Extract targets from Firebase config text/snippet")
    p.add_argument("--confirm-write", action="store_true", help="Enable write checks (DANGEROUS). Must be explicit.")
    p.add_argument("--upload-file", help="Local file path to upload to candidate storage buckets (requires --confirm-write).")
    p.add_argument("--upload-name", help="Name to use for uploaded object (filename). If --upload-folder provided, will prefix.")
    p.add_argument("--upload-folder", help="Folder (object prefix) to upload into. Example: pentest_results")
    p.add_argument("--cleanup", action="store_true", help="Attempt to delete uploaded artifacts after upload (best-effort).")
    p.add_argument("--out-json", help="Save full JSON report to this path.")
    p.add_argument("--out-csv", help="Save CSV summary to this path.")
    p.add_argument("--sleep", type=float, default=0.4, help="Delay between requests to be polite.")
    args = p.parse_args()

    global SLEEP
    SLEEP = args.sleep

    # Handle target extraction from config
    targets = []
    if args.targets:
        targets.extend(args.targets)
    
    if args.config_file:
        try:
            with open(args.config_file, 'r') as f:
                config_content = f.read()
            extracted = extract_firebase_info_from_config(config_content)
            targets.extend(extracted)
            print(f"[+] Extracted {len(extracted)} targets from config file: {extracted}")
        except Exception as e:
            print(f"[!] Error reading config file: {e}")
            return
    
    if args.config_text:
        extracted = extract_firebase_info_from_config(args.config_text)
        targets.extend(extracted)
        print(f"[+] Extracted {len(extracted)} targets from config text: {extracted}")
    
    if not targets:
        print("[!] No targets specified. Use --targets, --config-file, or --config-text")
        return
    
    # Remove duplicates
    targets = list(dict.fromkeys(targets))

    if (args.upload_file or args.cleanup) and not args.confirm_write:
        print("[!] Upload/cleanup requested but --confirm-write not set. Aborting write-capable operations.")
    if (args.upload_file and not args.upload_name):
        print("[!] --upload-file provided but --upload-name is required to control destination object name. Aborting.")
        return

    all_reports=[]
    for target in targets:
        print("="*80)
        print(f"[+] Running checks for target: {target}  (write enabled: {args.confirm_write})")
        report = run_checks(
            target=target,
            do_write=args.confirm_write,
            upload_file=args.upload_file,
            upload_name=args.upload_name,
            upload_folder=args.upload_folder,
            cleanup=args.cleanup
        )
        all_reports.append(report)
        # print brief human-friendly output
        # Realtime summary
        realtime = report["checks"].get("realtime", [])
        for r in realtime:
            print(f"[Realtime] {r['url']} -> status={r['status']}")
            if r['status'] == 200:
                print("  -> PUBLIC READ detected (snippet):", r['snippet'][:200].replace("\n"," "))
        # Firestore
        fs = report["checks"].get("firestore", {})
        print(f"[Firestore] {fs.get('url')} -> status={fs.get('status')}")
        if fs.get("status")==200:
            print("  -> Firestore default DB is readable (public).")
        # Storage
        for s in report["checks"].get("storage_guesses", []):
            print(f"[Storage] bucket_guess={s.get('bucket_guess')} status={s.get('status')} listable={s.get('listable')}")
        # Hosting
        for h in report["checks"].get("hosting", []):
            print(f"[Hosting] {h.get('url')} -> status={h.get('status')} config_like={h.get('config_like')}")
        # Functions
        for f in report["checks"].get("functions", []):
            print(f"[Functions] {f.get('url')} -> status={f.get('status')}")
        # Config endpoints
        for c in report["checks"].get("config_endpoints", []):
            print(f"[Config] {c.get('url')} -> status={c.get('status')} has_config={c.get('has_config_data')}")
            if c.get('has_config_data'):
                print("  -> Configuration data detected (snippet):", c['snippet'][:200].replace("\n", " "))
        # Write results summary (if any)
        if args.confirm_write:
            if "realtime_write" in report["checks"]:
                for w in report["checks"]["realtime_write"]["realtime_write"]:
                    print(f"[Realtime write test] {w['url']} put_status={w['put_status']} get_status={w['get_status']} delete_status={w['delete_status']}")
            if "firestore_write_test" in report["checks"]:
                print("[Firestore write test] create_status=", report["checks"]["firestore_write_test"].get("create_status"))
            if "storage_upload_results" in report["checks"]:
                for u in report["checks"]["storage_upload_results"]:
                    print(f"[Storage upload] bucket={u.get('bucket_attempt')} status={u.get('status')} resp_snippet={u.get('response_snippet')[:200]}")
                if args.cleanup:
                    for d in report["checks"].get("storage_delete_attempts", []):
                        print(f"[Storage delete attempt] {d.get('url')} status={d.get('status')}")

        print("="*80)
        time.sleep(0.6)

    # Save reports if requested
    if args.out_json:
        write_report_json(all_reports, args.out_json)
    if args.out_csv:
        write_report_csv(all_reports, args.out_csv)

    # Print summary of findings
    print_findings_summary(all_reports, args.confirm_write)

    print("[*] Completed. Remember to review findings and remove any test artifacts you created during authorized tests.")

if __name__ == "__main__":
    main()
