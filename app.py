import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, cast

import requests
from flask import Flask, jsonify, render_template
from requests.auth import HTTPBasicAuth

_url_base = os.getenv("URL_BASE")
_client_id = os.getenv("CLIENT_ID")
_client_secret = os.getenv("CLIENT_SECRET")

if not _url_base:
    raise RuntimeError("Missing URL_BASE environment variable.")

if not _client_id or not _client_secret:
    raise RuntimeError(
        "Missing CLIENT_ID or CLIENT_SECRET environment variables."
    )

API_BASE_URL = cast(str, _url_base)
TOKEN_ENDPOINT = "/oauth2/token"
STATUS_ENDPOINT = "/connect/grid/status"
GRID_ENDPOINT = "/connect/grid"
CA_CERT_PATH = os.getenv("CA_CERT", os.path.join(os.path.dirname(__file__), "so-ca.crt"))
REQUEST_TIMEOUT = float(os.getenv("TIMEOUT", "10"))

CLIENT_ID = cast(str, _client_id)
CLIENT_SECRET = cast(str, _client_secret)


@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: Optional[int] = None


app = Flask(__name__)


def build_url(path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{API_BASE_URL.rstrip('/')}/{path.lstrip('/')}"


def request_access_token() -> TokenResponse:
    url = build_url(TOKEN_ENDPOINT)
    response = requests.post(
        url,
        data={"grant_type": "client_credentials"},
        auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
        timeout=REQUEST_TIMEOUT,
        verify=CA_CERT_PATH,
    )
    response.raise_for_status()
    payload = response.json()
    return TokenResponse(
        access_token=payload["access_token"],
        token_type=payload.get("token_type", "Bearer"),
        expires_in=payload.get("expires_in"),
    )


def fetch_status(token: TokenResponse) -> dict:
    url = build_url(STATUS_ENDPOINT)
    headers = {"Authorization": f"Bearer {token.access_token}"}
    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=CA_CERT_PATH,
    )
    response.raise_for_status()
    return response.json()


def fetch_grid_nodes(token: TokenResponse) -> dict:
    url = build_url(GRID_ENDPOINT)
    headers = {"Authorization": f"Bearer {token.access_token}"}
    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=CA_CERT_PATH,
    )
    response.raise_for_status()
    return response.json()


def perform_node_operation(token: TokenResponse, node_id: str, operation: str) -> dict:
    url = build_url(f"/connect/gridmembers/{node_id}/{operation}")
    headers = {"Authorization": f"Bearer {token.access_token}"}
    response = requests.post(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=CA_CERT_PATH,
    )
    response.raise_for_status()
    return response.json() if response.text else {"status": "success"}


def _humanize_flag(flag: str) -> str:
    result = []
    for char in flag:
        if result and char.isupper():
            result.append(" ")
        result.append(char)
    humanized = "".join(result).replace("_", " ")
    return humanized.capitalize()


def _format_uptime(seconds: int) -> str:
    """Convert seconds to human-readable uptime format."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:  # Less than 1 hour
        minutes = seconds // 60
        return f"{minutes}m"
    elif seconds < 86400:  # Less than 1 day
        hours = seconds // 3600
        return f"{hours}h"
    elif seconds < 604800:  # Less than 1 week
        days = seconds // 86400
        return f"{days}d"
    else:  # Weeks or more
        weeks = seconds // 604800
        days = (seconds % 604800) // 86400
        if days > 0:
            return f"{weeks}w {days}d"
        return f"{weeks}w"


def evaluate_upstream(upstream: dict) -> dict:
    issues = []
    highlights = []
    notices = []

    alerts = upstream.get("alerts", {})
    new_alerts = alerts.get("newCount")
    if new_alerts:
        issues.append(f"{new_alerts} new alert(s) waiting")
    else:
        highlights.append("No new alerts")

    grid = upstream.get("grid", {})
    unhealthy_nodes = grid.get("unhealthyNodeCount")
    awaiting_reboot = grid.get("awaitingRebootNodeCount")
    total_nodes = grid.get("totalNodeCount")
    eps = grid.get("eps")

    if unhealthy_nodes:
        issues.append(f"{unhealthy_nodes} grid node(s) unhealthy")
    else:
        highlights.append("All grid nodes healthy")

    if awaiting_reboot:
        notices.append(f"{awaiting_reboot} node(s) awaiting reboot")

    detection_checks = []
    detections = upstream.get("detections", {})
    for system, flags in sorted(detections.items()):
        bad_flags = [
            _humanize_flag(name)
            for name, active in sorted(flags.items())
            if bool(active)
        ]
        detection_checks.append(
            {
                "name": system.replace("_", " ").title(),
                "ok": not bad_flags,
                "bad_flags": bad_flags,
            }
        )
        if bad_flags:
            issues.append(
                f"{system.replace('_', ' ').title()} requires attention: {', '.join(bad_flags)}"
            )
        else:
            highlights.append(f"{system.replace('_', ' ').title()} reporting healthy")

    overall = "healthy" if not issues else "degraded"

    return {
        "overall": overall,
        "issues": issues,
        "highlights": highlights,
        "notices": notices,
        "alerts": {
            "new": new_alerts,
        },
        "grid": {
            "total": total_nodes,
            "unhealthy": unhealthy_nodes,
            "awaiting_reboot": awaiting_reboot,
            "eps": eps,
        },
        "detections": detection_checks,
    }


def collect_status():
    token = request_access_token()
    upstream = fetch_status(token)
    evaluation = evaluate_upstream(upstream)
    return token, upstream, evaluation


@app.route("/health", methods=["GET"])
def health():
    try:
        token, status_payload, evaluation = collect_status()
        return jsonify({
            "status": "ok",
            "summary": evaluation,
            "upstream": status_payload,
            "token_expires_in": token.expires_in,
        })
    except requests.HTTPError as http_err:
        response = getattr(http_err, "response", None)
        status_code = response.status_code if response is not None else 502
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(http_err),
                    "details": getattr(response, "text", None),
                }
            ),
            status_code,
        )
    except requests.RequestException as req_err:
        return jsonify({"status": "error", "message": str(req_err)}), 502


@app.route("/", methods=["GET"])
def root():
    refreshed_at = datetime.now(timezone.utc)
    try:
        token, status_payload, evaluation = collect_status()
        return render_template(
            "status.html",
            summary=evaluation,
            upstream=status_payload,
            token_expires_in=token.expires_in,
            last_refreshed=refreshed_at,
        )
    except requests.HTTPError as http_err:
        response = getattr(http_err, "response", None)
        status_code = response.status_code if response is not None else 502
        return (
            render_template(
                "status.html",
                error=True,
                error_message=str(http_err),
                error_details=getattr(response, "text", None),
                last_refreshed=refreshed_at,
            ),
            status_code,
        )
    except requests.RequestException as req_err:
        return (
            render_template(
                "status.html",
                error=True,
                error_message=str(req_err),
                last_refreshed=refreshed_at,
            ),
            502,
        )


@app.route("/api/node/<node_id>/restart", methods=["POST"])
def restart_node(node_id):
    try:
        token = request_access_token()
        result = perform_node_operation(token, node_id, "restart")
        return jsonify({
            "status": "success",
            "message": f"Restart command sent to node {node_id}",
            "result": result
        })
    except requests.HTTPError as http_err:
        response = getattr(http_err, "response", None)
        status_code = response.status_code if response is not None else 502
        return jsonify({
            "status": "error",
            "message": str(http_err),
            "details": getattr(response, "text", None)
        }), status_code
    except requests.RequestException as req_err:
        return jsonify({
            "status": "error",
            "message": str(req_err)
        }), 502


@app.route("/nodes", methods=["GET"])
def nodes():
    refreshed_at = datetime.now(timezone.utc)
    try:
        token = request_access_token()
        grid_data = fetch_grid_nodes(token)
        
        # Handle response - can be a list or dict with "nodes" key
        if isinstance(grid_data, list):
            nodes_list = grid_data
        else:
            nodes_list = grid_data.get("nodes", [])
        
        all_nodes = []
        
        for node in nodes_list:
            # Parse processJson string into object
            process_json_raw = node.get("processJson", "{}")
            process_json = {}
            if process_json_raw:
                try:
                    process_json = json.loads(process_json_raw)
                except (json.JSONDecodeError, TypeError):
                    process_json = {"error": "Failed to parse processJson"}
            
            node_status = node.get("status", "Unknown").lower()
            connection_status = node.get("connectionStatus", "Unknown").lower()
            raw_role = node.get("role", "Unknown")
            
            # Parse role to extract the part after "so-"
            role_suffix = ""
            if raw_role.startswith("so-"):
                role_suffix = raw_role.replace("so-", "").replace("-", "")
            
            # Format the ID as {id}_{role_suffix}
            raw_id = node.get("id", "Unknown")
            formatted_id = f"{raw_id}_{role_suffix}" if role_suffix else raw_id
            
            # Categorize node status
            needs_reboot = (
                "pending reboot" in node_status 
                or node_status == "reboot" 
                or "restart" in node_status
            )
            
            is_unhealthy = (
                connection_status == "fault" 
                or (node_status != "ok" and not needs_reboot)
            )
            
            # For sorting: unhealthy=0, reboot=1, healthy=2
            if is_unhealthy:
                health_priority = 0
            elif needs_reboot:
                health_priority = 1
            else:
                health_priority = 2
            
            uptime_seconds = node.get("uptimeSeconds", 0)
            
            node_info = {
                "id": raw_id,
                "formattedId": formatted_id,
                "address": node.get("address", "Unknown"),
                "description": node.get("description", ""),
                "role": node.get("role", "Unknown"),
                "status": node.get("status", "Unknown"),
                "connectionStatus": node.get("connectionStatus", "Unknown"),
                "model": node.get("model", "Unknown"),
                "version": node.get("version", "Unknown"),
                "processJson": process_json,
                "processStatus": node.get("processStatus", "Unknown"),
                "cpuUsedPct": node.get("cpuUsedPct", 0),
                "memoryUsedPct": node.get("memoryUsedPct", 0),
                "diskUsedRootPct": node.get("diskUsedRootPct", 0),
                "productionEps": node.get("productionEps", 0),
                "consumptionEps": node.get("consumptionEps", 0),
                "uptimeSeconds": uptime_seconds,
                "uptimeFormatted": _format_uptime(uptime_seconds),
                "isUnhealthy": is_unhealthy,
                "needsReboot": needs_reboot,
                "healthPriority": health_priority,
            }
            
            all_nodes.append(node_info)
        
        # Sort nodes: unhealthy first, then reboot, then healthy
        all_nodes.sort(key=lambda n: (n["healthPriority"], n["id"]))
        
        unhealthy_count = sum(1 for n in all_nodes if n["isUnhealthy"])
        
        return render_template(
            "nodes.html",
            nodes=all_nodes,
            total_nodes=len(nodes_list),
            unhealthy_count=unhealthy_count,
            last_refreshed=refreshed_at,
        )
    except requests.HTTPError as http_err:
        response = getattr(http_err, "response", None)
        status_code = response.status_code if response is not None else 502
        return (
            render_template(
                "nodes.html",
                error=True,
                error_message=str(http_err),
                error_details=getattr(response, "text", None),
                last_refreshed=refreshed_at,
            ),
            status_code,
        )
    except requests.RequestException as req_err:
        return (
            render_template(
                "nodes.html",
                error=True,
                error_message=str(req_err),
                last_refreshed=refreshed_at,
            ),
            502,
        )


def create_app() -> Flask:
    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
