"""
STRIDE Threat Model Analyzer — Flask Application
=================================================
Main entry point. Defines all routes and wires together the modules.
"""

import json
import os
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    make_response,
    session,
    redirect,
    url_for,
    flash,
)

from modules.stride_engine import analyse_system, STRIDE_CATEGORIES
from modules.risk_calculator import enrich_threats, build_summary
from modules.report_generator import generate_text_report, generate_csv_report

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "stride-analyzer-dev-secret-2024")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Server-side assessment store (keyed by session ID).
# Avoids hitting the 4 KB browser cookie limit when threat lists are large.
_ASSESSMENT_STORE: dict = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_sample_system() -> dict:
    path = os.path.join(DATA_DIR, "sample_system.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _run_analysis(system: dict) -> tuple:
    """Run the full pipeline: identify threats, enrich with risk, build summary."""
    threats = analyse_system(system)
    threats = enrich_threats(threats)
    summary = build_summary(threats)
    return threats, summary


def _validate_system_form(form) -> tuple[dict | None, list[str]]:
    """Parse and validate the system form data. Returns (system_dict, errors)."""
    errors: list[str] = []

    name = form.get("system_name", "").strip()
    description = form.get("system_description", "").strip()

    if not name:
        errors.append("System name is required.")
    if not description:
        errors.append("System description is required.")

    # Components — at least one required
    component_names = form.getlist("component_name")
    component_types = form.getlist("component_type")
    component_descs = form.getlist("component_description")

    components = []
    for i, cname in enumerate(component_names):
        cname = cname.strip()
        if not cname:
            continue
        ctype = component_types[i].strip() if i < len(component_types) else "web_application"
        cdesc = component_descs[i].strip() if i < len(component_descs) else ""
        components.append({
            "id": f"c{i+1}",
            "name": cname,
            "type": ctype,
            "description": cdesc,
        })

    if not components:
        errors.append("At least one component is required.")

    # Data flows — optional
    flow_froms = form.getlist("flow_from")
    flow_tos = form.getlist("flow_to")
    flow_labels = form.getlist("flow_label")
    flow_protocols = form.getlist("flow_protocol")

    data_flows = []
    for i, ff in enumerate(flow_froms):
        ff = ff.strip()
        ft = flow_tos[i].strip() if i < len(flow_tos) else ""
        if not ff or not ft:
            continue
        data_flows.append({
            "id": f"df{i+1}",
            "from": ff,
            "to": ft,
            "label": flow_labels[i].strip() if i < len(flow_labels) else "",
            "protocol": flow_protocols[i].strip() if i < len(flow_protocols) else "HTTPS",
        })

    # Trust boundaries — optional
    tb_names = form.getlist("tb_name")
    tb_descs = form.getlist("tb_description")

    trust_boundaries = []
    for i, tbn in enumerate(tb_names):
        tbn = tbn.strip()
        if not tbn:
            continue
        trust_boundaries.append({
            "id": f"tb{i+1}",
            "name": tbn,
            "description": tb_descs[i].strip() if i < len(tb_descs) else "",
            "components": [],
        })

    if errors:
        return None, errors

    return {
        "name": name,
        "description": description,
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": trust_boundaries,
    }, []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _get_assessment():
    """Retrieve the current assessment from the server-side store."""
    aid = session.get("assessment_id")
    if aid and aid in _ASSESSMENT_STORE:
        return _ASSESSMENT_STORE[aid]
    return None


def _save_assessment(system, threats, summary):
    """Store an assessment server-side and record its key in the session cookie."""
    import uuid
    aid = session.get("assessment_id") or str(uuid.uuid4())
    _ASSESSMENT_STORE[aid] = {"system": system, "threats": threats, "summary": summary}
    session["assessment_id"] = aid


@app.route("/")
def index():
    """Home / Dashboard."""
    data = _get_assessment()
    threats = data["threats"] if data else None
    summary = data["summary"] if data else None
    system  = data["system"]  if data else None
    return render_template(
        "index.html",
        stride_categories=STRIDE_CATEGORIES,
        threats=threats,
        summary=summary,
        system=system,
    )


@app.route("/assessment", methods=["GET", "POST"])
def assessment():
    """New threat assessment form and results."""
    if request.method == "POST":
        action = request.form.get("action", "analyse")

        if action == "load_sample":
            system = _load_sample_system()
        else:
            system, errors = _validate_system_form(request.form)
            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template(
                    "assessment.html",
                    form_data=request.form,
                    threats=None,
                    summary=None,
                    system=None,
                )

        threats, summary = _run_analysis(system)
        _save_assessment(system, threats, summary)

        return render_template(
            "assessment.html",
            system=system,
            threats=threats,
            summary=summary,
            form_data=None,
        )

    # GET — show empty form
    return render_template(
        "assessment.html",
        system=None,
        threats=None,
        summary=None,
        form_data=None,
    )


@app.route("/sample")
def load_sample():
    """Run analysis on the built-in sample system and redirect to assessment."""
    system = _load_sample_system()
    threats, summary = _run_analysis(system)
    _save_assessment(system, threats, summary)
    return redirect(url_for("assessment") + "?loaded=sample")


@app.route("/diagram")
def diagram():
    """Interactive threat diagram page."""
    data   = _get_assessment()
    system = data["system"] if data else _load_sample_system()
    return render_template("diagram.html", system=system)


@app.route("/report")
def report():
    """Report view page."""
    data = _get_assessment()
    if not data:
        flash("No assessment found. Please run an assessment first.", "info")
        return redirect(url_for("assessment"))

    return render_template(
        "report.html",
        system=data["system"],
        threats=data["threats"],
        summary=data["summary"],
    )


@app.route("/download/text")
def download_text():
    """Download the current report as a plain text file."""
    data = _get_assessment()
    if not data:
        flash("No assessment found. Please run an assessment first.", "info")
        return redirect(url_for("assessment"))

    report_text = generate_text_report(data["system"], data["threats"], data["summary"])
    response = make_response(report_text)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="stride_report_{data["system"]["name"].replace(" ", "_")}.txt"'
    )
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


@app.route("/download/csv")
def download_csv():
    """Download the current report as a CSV file."""
    data = _get_assessment()
    if not data:
        flash("No assessment found. Please run an assessment first.", "info")
        return redirect(url_for("assessment"))

    csv_text = generate_csv_report(data["system"], data["threats"])
    response = make_response(csv_text)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="stride_threats_{data["system"]["name"].replace(" ", "_")}.csv"'
    )
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


@app.route("/api/analyse", methods=["POST"])
def api_analyse():
    """
    JSON API endpoint for programmatic access.
    POST body: { "system": { ... system dict ... } }
    Returns: { "threats": [...], "summary": {...} }
    """
    data = request.get_json(silent=True)
    if not data or "system" not in data:
        return jsonify({"error": "Request body must contain a 'system' key."}), 400

    system = data["system"]
    if not system.get("name"):
        return jsonify({"error": "System 'name' is required."}), 400
    if not system.get("components"):
        return jsonify({"error": "System must have at least one component."}), 400

    threats, summary = _run_analysis(system)
    return jsonify({"threats": threats, "summary": summary})


@app.route("/about")
def about():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
