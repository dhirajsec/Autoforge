from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from scan_control import orchestrate_security_scan
import os
import json

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/security-graph")
def serve_iam_graph(request: Request):
    profile_path = "configs/security_baseline.json"
    target_folder = "sample_tf"

    # 🚀 Run full orchestration: scan + render + query
    summary, image_path = orchestrate_security_scan(
        profile_path=profile_path,
        folder=target_folder,
        show_audit=True
    )

    if image_path and os.path.exists(image_path):
        filename = os.path.basename(image_path)
        timestamp = filename.replace("iam_graph_", "").replace(".png", "").replace("_", " ")

        # 📦 Save JSON summary alongside the image
        json_path = os.path.join("static/reports", filename.replace(".png", ".json"))
        try:
            with open(json_path, "w") as f:
                json.dump(summary, f, indent=4)
            print(f"✅ JSON summary saved to {json_path}")
        except Exception as e:
            print(f"⚠️ Failed to save summary: {e}")

        return templates.TemplateResponse(
            "security_graph.html",
            {
                "request": request,
                "timestamp": timestamp,
                "image_path": f"/static/reports/{filename}",
                "filename": filename,
                "summary": summary
            }
        )
    else:
        return {"error": "No graph found. Scan might have failed."}