from fastapi import FastAPI, Query,Request,Form
from fastapi.responses import HTMLResponse,FileResponse,RedirectResponse
from fastapi.templating import Jinja2Templates
from terraform_linter import scan_terraform_file, scan_folder,load_config
from report_generator import format_as_html, format_as_markdown, summarize_scan
from datetime import datetime
from scan_control import load_profile, save_profile, save_target_folder
from collections import defaultdict
import json
import os
from rules.rule_engine import run_scan
from routes.security_routes import router as security_router
from routes import security_routes
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(security_routes.router)
os.makedirs("reports", exist_ok=True)
templates = Jinja2Templates(directory="templates")
# Path to the log file
log_path = "reports/refresh_log.json"
# Initialize with empty list if the file doesn't exist
if not os.path.exists(log_path):
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump([], f)
    print("✅ refresh_log.json created and initialized with []")
else:
    print("🔁 refresh_log.json already exists")
def profile_metadata_coverage():
    report = {
        "total": 0,
        "with_meta": 0,
        "missing_comment": [],
        "missing_tags": [],
        "missing_timestamp": [],
        "no_meta": []
    }

    for fname in os.listdir("configs"):
        if fname.endswith(".json"):
            report["total"] += 1
            try:
                with open(os.path.join("configs", fname), encoding="utf-8") as f:
                    data = json.load(f)

                meta = data.get("meta")

                if not meta:
                    report["no_meta"].append(fname)
                    continue

                report["with_meta"] += 1

                if not meta.get("comment"):
                    report["missing_comment"].append(fname)
                if not meta.get("tags"):
                    report["missing_tags"].append(fname)
                if not meta.get("timestamp"):
                    report["missing_timestamp"].append(fname)

            except Exception as e:
                print(f"⚠️ Error parsing {fname}: {e}")

    print("📊 Metadata coverage report:", report)  # Optional debug
    return report
app.include_router(security_router)
@app.get("/")
def home():
    return {"message": "AutoForge is live and scanning 👷‍♂️"}

@app.get("/scan")
def scan(file: str = Query(default="sample.tf")):
    return {"results": scan_terraform_file(file)}

@app.get("/scan-folder")
def scan_folder_endpoint(folder: str = Query(default=".")):
    return {"folder_scan": scan_folder(folder)}

@app.get("/report", response_class=HTMLResponse)
def get_html_report(folder: str = Query(default="."), save: bool = Query(default=False)):
    scan = scan_folder(folder)
    report = format_as_html(scan)
    if save:
        with open("report.html", "w", encoding="utf-8") as f:
            f.write(report)
    return report
from report_generator import format_as_markdown
from fastapi.responses import PlainTextResponse

@app.get("/report-md", response_class=PlainTextResponse)
def get_markdown_report(folder: str = Query(default="."), save: bool = Query(default=False)):
    scan = scan_folder(folder)
    report = format_as_markdown(scan)
    if save:
        with open("report.md", "w", encoding="utf-8") as f:
            f.write(report)
    return report
import json
import zipfile
from fastapi.responses import JSONResponse

@app.get("/report-severity")
def report_by_severity(level: str = Query(default="high")):
    history_dir = "reports/history"
    files = sorted(os.listdir(history_dir), reverse=True)

    for file in files:
        if file.endswith("_scan.json"):
            with open(os.path.join(history_dir, file), encoding="utf-8") as f:
                data = json.load(f)
                filtered_results = {}
                for filename, issues in data["results"].items():
                    filtered = [
                        i for i in issues
                        if i.get("severity", "") == level
                    ]
                    if filtered:
                        filtered_results[filename] = filtered
                return {
                    "timestamp": data["timestamp"],
                    "profile": data["profile"],
                    "severity": level,
                    "filtered_results": filtered_results
                }

    return {"message": "No scan history found."}
@app.get("/profiles")
def list_profiles():
    profiles = [
        f for f in os.listdir(".")
        if f.endswith(".json") and "config" in f.lower()
    ]
    return {"available_profiles": sorted(profiles)}
@app.get("/profile-content")
def get_profile_content(name: str = Query(...)):
    path = os.path.join(".", name)
    if not os.path.exists(path):
        return {"error": f"Profile file '{name}' not found."}
    try:
        with open(path, encoding="utf-8") as f:
            content = json.load(f)
        return {"profile_name": name, "rules": content}
    except json.JSONDecodeError:
        return {"error": f"Profile file '{name}' is not valid JSON."}

@app.post("/save-profile")
async def save_profile(request: Request):
    form = await request.form()
    profile_name = form.get("profile_name")
    rules_json = form.get("rules_json")
    strict_mode_value = form.get("strict_mode_value", "false")

    rules = json.loads(rules_json)
    config = {
        "strict_mode": strict_mode_value == "true",
        "rules": rules
    }

    outpath = os.path.join("configs", profile_name)
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"💾 Profile saved as: {profile_name}")
    return RedirectResponse("/pre-scan-setup?profile_saved=true", status_code=303)
def load_profile_metadata():
    activity = []
    for fname in os.listdir("configs"):
        if fname.endswith(".json"):
            try:
                with open(os.path.join("configs", fname), encoding="utf-8") as f:
                    data = json.load(f)

                meta = data.get("meta", {})

                # Log each parsed item for quick debugging
                item = {
                    "name": fname,
                    "timestamp": meta.get("timestamp", "—"),
                    "comment": meta.get("comment", ""),
                    "tags": meta.get("tags", []),
                    "created_by": meta.get("created_by", "—")
                }
                activity.append(item)

            except Exception as e:
                print(f"⚠️ Metadata error in {fname}: {e}")

    print("📋 Timeline items loaded:", activity)  # Debug log
    return sorted(activity, key=lambda x: x["timestamp"], reverse=True)
def summarize_security_tags():
    summary = []

    for fname in os.listdir("configs"):
        if fname.endswith(".json"):
            try:
                with open(os.path.join("configs", fname), encoding="utf-8") as f:
                    data = json.load(f)

                rules = data.get("rules", {})
                indicators = []

                if rules.get("enforce_encryption", {}).get("enabled"):
                    indicators.append("🔐 Encrypted")
                if rules.get("require_tags", {}).get("enabled"):
                    indicators.append("🧍 Tags Required")
                if rules.get("enable_public_access_check", {}).get("enabled"):
                    indicators.append("🚫 Public Access Scan")

                summary.append({
                    "name": fname,
                    "security_tags": indicators
                })

            except Exception as e:
                print(f"⚠️ Security tag error in {fname}:", e)

    return summary
# 🔧 Route: /manage-profiles
@app.get("/manage-profiles", response_class=HTMLResponse)
def manage_profiles(request: Request):
    filename = request.query_params.get("edit")
    merge_param = request.query_params.get("merge")
    profiles = sorted([f for f in os.listdir("configs") if f.endswith(".json")])

    # Profile editing data
    edit_data = {}
    if filename:
        try:
            with open(os.path.join("configs", filename), encoding="utf-8") as f:
                edit_data = json.load(f)
        except:
            filename = None

    # 🧬 Merge Preview + Conflict Summary
    merge_data = None
    if merge_param and "__" in merge_param:
        try:
            p1, p2 = merge_param.split("__")
            with open(os.path.join("configs", p1), encoding="utf-8") as f1, \
                 open(os.path.join("configs", p2), encoding="utf-8") as f2:
                data1 = json.load(f1)
                data2 = json.load(f2)

            rules1 = data1.get("rules", {})
            rules2 = data2.get("rules", {})
            all_rules = sorted(set(rules1) | set(rules2))

            conflicts = []
            for rule in all_rules:
                r1 = rules1.get(rule)
                r2 = rules2.get(rule)
                if r1 and r2:
                    if r1.get("enabled") != r2.get("enabled") or r1.get("optional") != r2.get("optional"):
                        conflicts.append({
                            "rule": rule,
                            "p1": r1,
                            "p2": r2,
                            "status": "conflict"
                        })

            merge_data = {
                "p1": p1,
                "p2": p2,
                "rules1": rules1,
                "rules2": rules2,
                "strict1": data1.get("strict_mode", False),
                "strict2": data2.get("strict_mode", False),
                "all_rules": all_rules,
                "conflicts": conflicts
            }
        except Exception as e:
            print("⚠️ Merge preview failed:", e)

    # Render page context
    context = {
    "request": request,
    "profiles": profiles,
    "edit_profile": filename,
    "edit_rules": edit_data.get("rules", {}),
    "strict_mode": edit_data.get("strict_mode", False),
    "merge_profiles": merge_data,
    "recent_activity": load_profile_metadata()[:10],
    "meta_report": profile_metadata_coverage(),
    "security_overview": summarize_security_tags()  # 🆕 Security Module
}

    if len(profiles) < 2:
        context["message"] = "⚠️ Not enough profiles to compare or merge."

    return templates.TemplateResponse("profile_manage.html", context)
@app.post("/save-profile")
async def save_profile(
    request: Request,
    profile_name: str = Form(...),
    rules_json: str = Form(...),
    strict_mode_value: str = Form(None),
    profile_comment: str = Form("")  # new field from HTML form
):
    try:
        config_data = {
            "strict_mode": strict_mode_value == "true",
            "rules": json.loads(rules_json),
            "meta": {
                "created_by": "Dhiraj",
                "timestamp": datetime.utcnow().isoformat(),
                "comment": profile_comment,
                "tags": ["new"]
            }
        }

        outpath = os.path.join("configs", profile_name)
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)

        print(f"🆕 Profile created: {profile_name}")
        return RedirectResponse("/pre-scan-setup?profile_saved=true", status_code=303)

    except Exception as e:
        return templates.TemplateResponse("profile_manage.html", {
            "request": request,
            "message": f"❌ Save error: {e}"
        })
@app.get("/compare-profiles", response_class=HTMLResponse)
def compare_profiles(request: Request):
    p1 = request.query_params.get("p1")
    p2 = request.query_params.get("p2")
    profiles = sorted([f for f in os.listdir("configs") if f.endswith(".json")])
    diff_result = []

    data1 = data2 = {}

    if p1 and p2:
        try:
            with open(os.path.join("configs", p1), encoding="utf-8") as f1, \
                 open(os.path.join("configs", p2), encoding="utf-8") as f2:
                data1 = json.load(f1)
                data2 = json.load(f2)

            rules1 = data1.get("rules", {})
            rules2 = data2.get("rules", {})
            all_keys = set(rules1) | set(rules2)

            for key in sorted(all_keys):
                r1 = rules1.get(key)
                r2 = rules2.get(key)
                diff_result.append({
                    "rule": key,
                    "p1_enabled": r1.get("enabled", False) if r1 else False,
                    "p2_enabled": r2.get("enabled", False) if r2 else False,
                    "p1_optional": r1.get("optional", False) if r1 else False,
                    "p2_optional": r2.get("optional", False) if r2 else False,
                })
        except Exception as e:
            return templates.TemplateResponse("profile_manage.html", {
                "request": request,
                "profiles": profiles,
                "message": f"❌ Error loading comparison: {e}"
            })

    return templates.TemplateResponse("profile_manage.html", {
        "request": request,
        "profiles": profiles,
        "selected_p1": p1,
        "selected_p2": p2,
        "strict_p1": data1.get("strict_mode"),
        "strict_p2": data2.get("strict_mode"),
        "diff_result": diff_result
    })
@app.get("/merge-profiles")
def merge_profiles(request: Request):
    p1 = request.query_params.get("p1")
    p2 = request.query_params.get("p2")

    if not p1 or not p2:
        return RedirectResponse(url="/manage-profiles", status_code=303)

    # 🛩️ Forward to manage view with merge context
    return RedirectResponse(url=f"/manage-profiles?merge={p1}__{p2}", status_code=303)

@app.post("/save-merged-profile")
async def save_merged_profile(request: Request):
    form = await request.form()
    p1 = form.get("p1")
    p2 = form.get("p2")
    strict_choice = form.get("strict_mode")
    new_name = form.get("new_profile_name")
    comment = form.get("merge_comment", "")
    rule_choices = {key: form.get(key) for key in form.keys() if key not in ["p1", "p2", "strict_mode", "new_profile_name", "merge_comment"]}

    # Load profiles
    with open(os.path.join("configs", p1), encoding="utf-8") as f1, \
         open(os.path.join("configs", p2), encoding="utf-8") as f2:
        data1 = json.load(f1)
        data2 = json.load(f2)

    # Merge logic
    merged = {
        "strict_mode": data1.get("strict_mode", False) if strict_choice == "p1" else data2.get("strict_mode", False),
        "rules": {},
        "meta": {
            "created_by": "Dhiraj",
            "timestamp": datetime.utcnow().isoformat(),
            "comment": comment,
            "tags": ["merged"]
        }
    }

    for rule, source in rule_choices.items():
        selected = data1["rules"].get(rule) if source == "p1" else data2["rules"].get(rule)
        if selected:
            merged["rules"][rule] = selected

    with open(os.path.join("configs", new_name), "w", encoding="utf-8") as out:
        json.dump(merged, out, indent=2)

    return RedirectResponse(url="/manage-profiles", status_code=303)
@app.get("/report-trends")
def scan_trends():
    history_dir = "reports/history"
    trend_data = []

    for file in sorted(os.listdir(history_dir)):
        if file.endswith("_scan.json"):
            try:
                with open(os.path.join(history_dir, file), encoding="utf-8") as f:
                    data = json.load(f)
                trend_data.append({
                    "timestamp": data.get("timestamp", file.replace("_scan.json", "")),
                    "score": data.get("summary", {}).get("score", 0),
                    "failed": data.get("summary", {}).get("failed", 0),
                    "warnings": data.get("summary", {}).get("warnings", 0),
                    "passed": data.get("summary", {}).get("passed", 0),
                    "files": data.get("summary", {}).get("files", 0)
                })
            except Exception:
                continue

    return {"trends": trend_data}
@app.get("/scan-history")
def get_scan_history(name: str = Query(...)):
    path = os.path.join("reports/history", name)
    if not os.path.exists(path):
        return {"error": f"No file named '{name}' found."}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format."}

@app.get("/report-package")
def report_package(
    folder: str = Query(default="."),
    download: bool = Query(default=False),
    threshold: int = Query(default=0),
    profile: str = Query(default="config.json")
):
    config = load_config(profile)
    scan = scan_folder(folder, config=config)
    summary = summarize_scan(scan)
    score = summary["score"]
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    history_path = f"reports/history/{timestamp}_scan.json"
    os.makedirs("reports/history", exist_ok=True)
    

    # Save scan history
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "profile": profile,
            "folder": folder,
            "score": score,
            "summary": summary,
            "results": scan
        }, f, indent=4)

    html_report = format_as_html(scan)
    markdown_report = format_as_markdown(scan)
    json_report = json.dumps(scan, indent=4)

    # Save raw reports
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html_report)
    with open("report.md", "w", encoding="utf-8") as f:
        f.write(markdown_report)
    with open("scan_results.json", "w", encoding="utf-8") as f:
        f.write(json_report)

    # Score enforcement logic
    if threshold > 0 and score < threshold:
        warning = {
            "message": f"🚨 Scan score {score}% is below required threshold of {threshold}%",
            "compliance_score": score,
            "status": "non-compliant",
            "report_available": True
        }
        return JSONResponse(content=warning)

    # Normal download path
    if download:
        with zipfile.ZipFile("autoforge_report.zip", "w") as zipf:
            zipf.write("report.html")
            zipf.write("report.md")
            zipf.write("scan_results.json")
        return FileResponse("autoforge_report.zip", media_type="application/zip", filename="autoforge_report.zip")

    # Normal preview path
    return HTMLResponse(content=html_report)



    return JSONResponse(content={"message": "✅ Report package generated", "file": "autoforge_report.zip"})
@app.get("/dashboard")
def get_dashboard():
    # Load latest scan history
    history_dir = "reports/history"
    latest_file = None
    for file in sorted(os.listdir(history_dir), reverse=True):
        if file.endswith("_scan.json"):
            latest_file = file
            break

    history = {}
    if latest_file:
        with open(os.path.join(history_dir, latest_file), encoding="utf-8") as f:
            history = json.load(f)

    # Load profile content
    profile_name = history.get("profile", "config.json")
    profile_path = os.path.join(".", profile_name)
    profile = {}
    if os.path.exists(profile_path):
        with open(profile_path, encoding="utf-8") as f:
            profile = json.load(f)

    # Load trends
    trends = []
    for file in sorted(os.listdir(history_dir)):
        if file.endswith("_scan.json"):
            with open(os.path.join(history_dir, file), encoding="utf-8") as f:
                data = json.load(f)
                trends.append({
                    "timestamp": data.get("timestamp"),
                    "score": data.get("summary", {}).get("score", 0)
                })

    return {
        "latest_scan": history,
        "profile": {
            "name": profile_name,
            "rules": profile
        },
        "scan_trends": trends
    }
def summarize_security_tags():
    summary = []

    for fname in os.listdir("configs"):
        if fname.endswith(".json"):
            try:
                with open(os.path.join("configs", fname), encoding="utf-8") as f:
                    data = json.load(f)
                rules = data.get("rules", {})
                indicators = []

                if rules.get("enforce_encryption", {}).get("enabled"):
                    indicators.append("🔐 Encrypted")
                if rules.get("require_tags", {}).get("enabled"):
                    indicators.append("🧍 Tags Required")
                if rules.get("enable_public_access_check", {}).get("enabled"):
                    indicators.append("🚫 Public Access Scan")

                summary.append({
                    "name": fname,
                    "security_tags": indicators
                })

            except Exception as e:
                print(f"⚠️ Security tag error in {fname}:", e)

    return summary

# 🚦 Main dashboard route
@app.get("/dashboard-html", response_class=HTMLResponse)
def dashboard_html(request: Request, name: str = None, config_saved: bool = False):
    history_dir = "reports/history"
    config_path = os.path.join("configs", "config.json")

    # 🔍 Load current rule config
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)
    strict_mode = config.get("strict_mode", False)
    profile_rules = config.get("rules", {})

    # 🗂 Load scan history
    scan_files = sorted([
        f for f in os.listdir(history_dir)
        if f.endswith("_scan.json")
    ], reverse=True)

    scan_file = name if name else (scan_files[0] if scan_files else None)
    if not scan_file:
        return HTMLResponse(content="No scan history found", status_code=404)

    with open(os.path.join(history_dir, scan_file), encoding="utf-8") as f:
        history = json.load(f)

    # 📈 Scan trends
    trends = []
    for f in scan_files:
        try:
            with open(os.path.join(history_dir, f), encoding="utf-8") as f_data:
                data = json.load(f_data)
                trends.append({
                    "timestamp": data.get("timestamp", "unknown"),
                    "score": data.get("summary", {}).get("score", 0)
                })
        except Exception:
            continue

    # 🔕 Rule suppression parser (inline function)
    def extract_suppressions(file_path):
        suppressed = set()
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    if "# skip-rule:" in line:
                        tag = line.split("# skip-rule:")[-1].strip().split()[0]
                        suppressed.add(tag)
        except Exception:
            pass
        return suppressed

    # 🧠 Severity grouping with suppression
    grouped = defaultdict(list)
    for file, issues in history.get("results", {}).items():
        file_path = os.path.join(history.get("folder", ""), file)
        suppressed = extract_suppressions(file_path)

        for issue in issues:
            if isinstance(issue, dict):
                rule = issue.get("rule")
                severity = issue.get("severity", "Info")
                if rule and rule in suppressed:
                    continue  # 🔕 Skip suppressed rule

                grouped[severity].append({
                    "file": file,
                    "line": issue.get("line", "N/A"),
                    "message": issue.get("message", str(issue))
                })

    # 📊 Rule hit stats
    rule_stats = {rule: 0 for rule in profile_rules}
    for file, issues in history.get("results", {}).items():
        for issue in issues:
            if isinstance(issue, dict):
                rule_key = issue.get("rule")
                if rule_key and rule_key in rule_stats:
                    rule_stats[rule_key] += 1

    # 🛡️ Security Tags Summary
    security_summary = summarize_security_tags()

    # 🖼️ Render dashboard
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "timestamp": history.get("timestamp", "N/A"),
        "profile_name": "config.json",
        "folder": history.get("folder", "N/A"),
        "score": history.get("summary", {}).get("score", 0),
        "results": history.get("results", {}),
        "profile_rules": profile_rules,
        "trends": trends,
        "grouped": grouped,
        "scan_files": scan_files,
        "rule_stats": rule_stats,
        "strict_mode": strict_mode,
        "config_saved": config_saved,
        "security_overview": security_summary
    })
@app.get("/compare-scan")
def compare_scans(first: str = Query(...), second: str = Query(...)):
    dir_path = "reports/history"
    first_path = os.path.join(dir_path, first)
    second_path = os.path.join(dir_path, second)

    if not os.path.exists(first_path) or not os.path.exists(second_path):
        return {"error": "One or both scan files not found."}

    with open(first_path, encoding="utf-8") as f1, open(second_path, encoding="utf-8") as f2:
        data1 = json.load(f1)["results"]
        data2 = json.load(f2)["results"]

    delta = {}
    files = set(data1.keys()).union(set(data2.keys()))

    for file in files:
        old_issues = set(str(i) for i in data1.get(file, []))
        new_issues = set(str(i) for i in data2.get(file, []))

        added = sorted(new_issues - old_issues)
        removed = sorted(old_issues - new_issues)

        if added or removed:
            delta[file] = {
                "added": added,
                "removed": removed
            }

    return {
        "comparison": {
            "first": first,
            "second": second,
            "delta": delta
        }
    }
from fastapi.responses import HTMLResponse
from datetime import datetime
import os, json
def extract_high_risk_hits(results):
    risk_map = defaultdict(int)
    for file, issues in results.items():
        for issue in issues:
            if isinstance(issue, dict):
                severity = issue.get("severity", "")
                rule = issue.get("rule")
                if rule and severity in ["Critical", "High"]:
                    risk_map[rule] += 1
    return risk_map

@app.get("/dashboard-html", response_class=HTMLResponse)
def dashboard_html(request: Request, name: str = None, config_saved: bool = False):
    history_dir = "reports/history"
    config_path = os.path.join("configs", "config.json")

    # 🔍 Load current rule config
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)
    strict_mode = config.get("strict_mode", False)
    profile_rules = config.get("rules", {})

    # 🗂 Load scan history
    scan_files = sorted([
        f for f in os.listdir(history_dir)
        if f.endswith("_scan.json")
    ], reverse=True)

    scan_file = name if name else (scan_files[0] if scan_files else None)
    if not scan_file:
        return HTMLResponse(content="No scan history found", status_code=404)

    with open(os.path.join(history_dir, scan_file), encoding="utf-8") as f:
        history = json.load(f)

    # 📈 Scan trends
    trends = []
    for f in scan_files:
        try:
            with open(os.path.join(history_dir, f), encoding="utf-8") as f_data:
                data = json.load(f_data)
                trends.append({
                    "timestamp": data.get("timestamp", "unknown"),
                    "score": data.get("summary", {}).get("score", 0)
                })
        except Exception:
            continue

    # 🔕 Rule suppression parser
    def extract_suppressions(file_path):
        suppressed = set()
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    if "# skip-rule:" in line:
                        tag = line.split("# skip-rule:")[-1].strip().split()[0]
                        suppressed.add(tag)
        except Exception as e:
            print(f"⚠️ Suppression parsing error in {file_path}: {e}")
        return suppressed

    # 🧠 Severity grouping with suppression
    grouped = defaultdict(list)
    for file, issues in history.get("results", {}).items():
        file_path = os.path.join(history.get("folder", ""), file)
        suppressed = extract_suppressions(file_path)
        print(f"🔍 Suppressed rules in {file}: {suppressed}")

        for issue in issues:
            if isinstance(issue, dict):
                rule = issue.get("rule")
                severity = issue.get("severity", "Info")

                if rule and rule in suppressed:
                    print(f"⛔ Skipping suppressed rule → '{rule}' in {file}")
                    continue

                grouped[severity].append({
                    "file": file,
                    "line": issue.get("line", "N/A"),
                    "message": issue.get("message", str(issue))
                })

    # 📊 Rule hit stats
    rule_stats = {rule: 0 for rule in profile_rules}
    for file, issues in history.get("results", {}).items():
        for issue in issues:
            if isinstance(issue, dict):
                rule_key = issue.get("rule")
                if rule_key and rule_key in rule_stats:
                    rule_stats[rule_key] += 1

    # 🛡️ Security Tags Summary
    security_summary = summarize_security_tags()

    # 🖼️ Render dashboard
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "timestamp": history.get("timestamp", "N/A"),
        "profile_name": "config.json",
        "folder": history.get("folder", "N/A"),
        "score": history.get("summary", {}).get("score", 0),
        "results": history.get("results", {}),
        "profile_rules": profile_rules,
        "trends": trends,
        "grouped": grouped,
        "scan_files": scan_files,
        "rule_stats": rule_stats,
        "strict_mode": strict_mode,
        "config_saved": config_saved,
        "security_overview": security_summary
    })
@app.get("/refresh-history", response_class=HTMLResponse)
def refresh_history():
    log_file = "reports/refresh_log.json"
    timestamps = []

    try:
        with open(log_file, encoding="utf-8") as f:
            timestamps = json.load(f)
            if not isinstance(timestamps, list):
                timestamps = []
    except (FileNotFoundError, json.JSONDecodeError):
        timestamps = []

    # Build HTML
    if not timestamps:
        return HTMLResponse(content="<h1>No refresh events yet.</h1>")
    
    html = "<h1>📄 Refresh History</h1><ul>"
    for t in timestamps:
        html += f"<li>🔄 {t}</li>"
    html += "</ul>"
    return HTMLResponse(content=html)
def load_profile():
    with open("config.json", encoding="utf-8") as f:
        config = json.load(f)
    return {
        "rules": config.get("rules", {}),
        "strict_mode": config.get("strict_mode", False)
    }

@app.get("/pre-scan-setup", response_class=HTMLResponse)
def pre_scan_setup(request: Request):
    configs_dir = "configs"
    profiles = sorted([
        f for f in os.listdir(configs_dir)
        if f.endswith(".json")
    ])
    active_profile = "config.json"  # or choose based on logic

    with open(os.path.join(configs_dir, active_profile), encoding="utf-8") as f:
        config = json.load(f)

    profile_data = {
        "rules": config.get("rules", {}),
        "strict_mode": config.get("strict_mode", False)
    }

    return templates.TemplateResponse("pre_scan.html", {
        "request": request,
        "profile": profile_data,
        "profiles": profiles,
        "active": active_profile
    })

@app.post("/run-scan")
async def run_scan(request: Request):
    form = await request.form()
    scan_folder = form.get("scan_folder")
    profile_name = form.get("profile", "config.json")  # Default fallback

    # Load selected config from /configs folder
    config_path = os.path.join("configs", profile_name)
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    strict_mode = config.get("strict_mode", False)
    rules = config.get("rules", {})
    folder_path = os.path.join(".", scan_folder)
    violations = []

    def should_run(rule_name: str) -> bool:
        r = rules.get(rule_name, {})
        return r.get("enabled", False) and (strict_mode or not r.get("optional", False))

    for file in os.listdir(folder_path):
        if not file.endswith(".tf"):
            continue
        path = os.path.join(folder_path, file)
        with open(path, encoding="utf-8") as f:
            content = f.read()

        if should_run("enable_https_check") and "http" in content:
            violations.append({
                "file": file,
                "line": 3,
                "message": "🚫 HTTPS traffic not enforced",
                "severity": "Info",
                "rule": "enable_https_check"
            })

        if should_run("enable_public_access_check") and "public" in content:
            violations.append({
                "file": file,
                "line": 5,
                "message": "🌐 Public access detected",
                "severity": "High",
                "rule": "enable_public_access_check"
            })

        if should_run("enable_replication_check") and "replication" not in content:
            violations.append({
                "file": file,
                "line": 7,
                "message": "🔁 Replication missing",
                "severity": "Medium",
                "rule": "enable_replication_check"
            })

        # Add other rules as needed...

    grouped_results = {}
    for file in os.listdir(folder_path):
        if file.endswith(".tf"):
            grouped_results[file] = [v for v in violations if v["file"] == file]

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outpath = f"reports/history/{timestamp}_scan.json"
    os.makedirs("reports/history", exist_ok=True)
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "folder": scan_folder,
            "profile": profile_name,
            "summary": { "score": 100 if not violations else 85 },
            "results": grouped_results
        }, f, indent=2)

    print(f"📁 Scan run using profile: {profile_name}")
    return RedirectResponse("/dashboard-html?config_saved=true", status_code=303)
@app.post("/update-profile")
async def update_profile(request: Request):
    form_data = await request.form()

    # Load profile
    profile_path = "config.json"
    with open(profile_path, encoding="utf-8") as f:
        profile = json.load(f)

    # Update rule toggles
    for key in profile:
        profile[key] = key in form_data

    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)

    return RedirectResponse(url="/dashboard-html", status_code=303)
@app.get("/export")
def export_scan():
    latest_file = get_latest_history_file()
    with open(latest_file, encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(content=data)
@app.post("/toggle-strict")
def toggle_strict():
    config_path = "config.json"
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    config["strict_mode"] = not config.get("strict_mode", False)

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print("🔄 Strict mode toggled to:", config["strict_mode"])
    return RedirectResponse("/dashboard-html", status_code=303)