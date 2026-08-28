import html
import ipaddress
import socket
from urllib.parse import urlparse

import requests
import streamlit as st


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def _normalize_url(value: str) -> str:
    target = value.strip()
    if not target:
        return ""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target


def _is_private_or_local(hostname: str) -> bool:
    if not hostname:
        return True

    host = hostname.strip().lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        pass

    try:
        for result in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(result[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return True
    except Exception:
        return True

    return False


def _content_length_label(headers: requests.structures.CaseInsensitiveDict) -> str:
    length = headers.get("Content-Length")
    if not length:
        return "Unknown (Chunked Transfer)"
    try:
        size = int(length)
    except ValueError:
        return length
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"


def _cookie_flags(headers: requests.structures.CaseInsensitiveDict) -> str:
    cookies = headers.get("Set-Cookie")
    if not cookies:
        return "No Set-Cookie header"

    flags = []
    lower = cookies.lower()
    if "secure" in lower:
        flags.append("Secure")
    if "httponly" in lower:
        flags.append("HttpOnly")
    if "samesite" in lower:
        flags.append("SameSite")
    return ", ".join(flags) if flags else "Missing security flags"


def _server_version_exposed(server_value: str) -> bool:
    if not server_value:
        return False
    return bool(
        "/" in server_value
        or any(char.isdigit() for char in server_value)
    )


def _is_limited_response(status_code: int) -> bool:
    return status_code != 200


def _redirect_chain(history: list[str]) -> str:
    if len(history) <= 1:
        return "None"
    return " -> ".join(history)


def _score_headers(
    headers: requests.structures.CaseInsensitiveDict,
    cookie_value: str,
    final_url: str,
    server_version_exposed: bool,
    status_code: int,
) -> tuple[int, list[str], list[str], list[str], list[str], bool]:
    enabled = []
    not_observed = []
    informational = []
    recommendations = []
    significant_concerns = False
    score = 0.0
    limited_response = _is_limited_response(status_code)

    if urlparse(final_url).scheme == "https":
        score += 2.5
        enabled.append("HTTPS final response")
    else:
        significant_concerns = True
        recommendations.append("Consider serving the final response over HTTPS where possible.")

    weighted_headers = {
        "Strict-Transport-Security": 2.0,
        "Content-Security-Policy": 1.25,
        "X-Content-Type-Options": 1.0,
        "X-Frame-Options": 1.0,
        "Referrer-Policy": 0.75,
    }

    for header, weight in weighted_headers.items():
        if headers.get(header):
            enabled.append(header)
            score += weight
        else:
            not_observed.append(header)
            if limited_response:
                continue
            if header == "Strict-Transport-Security" and urlparse(final_url).scheme == "https":
                recommendations.append("Consider enabling Strict-Transport-Security on HTTPS responses.")
                significant_concerns = True
            elif header == "Content-Security-Policy":
                recommendations.append("Consider implementing a Content Security Policy for pages that render active content.")
            elif header == "Referrer-Policy":
                recommendations.append("Consider enabling Referrer-Policy to control referrer data shared with other origins.")
            elif header == "X-Content-Type-Options":
                recommendations.append("Consider setting X-Content-Type-Options to reduce MIME-sniffing ambiguity.")

    if headers.get("Permissions-Policy"):
        enabled.append("Permissions-Policy")
        score += 0.5
    else:
        informational.append("Permissions-Policy")

    if cookie_value == "Secure, HttpOnly, SameSite":
        score += 2.0
    elif cookie_value in {"Secure, HttpOnly", "Secure, SameSite", "HttpOnly, SameSite"}:
        score += 1.25
        if not limited_response:
            recommendations.append("Consider using Secure, HttpOnly, and SameSite together for sensitive cookies.")
    elif cookie_value == "No Set-Cookie header":
        informational.append("No Set-Cookie header")
    else:
        not_observed.append("Complete cookie security flags")
        if not limited_response:
            recommendations.append("Review Set-Cookie flags and consider Secure, HttpOnly, and SameSite where applicable.")
            significant_concerns = True

    if headers.get("Cache-Control"):
        score += 0.5
        informational.append("Cache-Control observed")
    else:
        informational.append("Cache-Control not observed")

    if server_version_exposed:
        recommendations.append("Consider reducing server version disclosure if operationally feasible.")
        significant_concerns = True
    else:
        score += 0.75

    if limited_response:
        informational.append(
            f"Received HTTP {_status_code_text(status_code)}; this response may expose a reduced or endpoint-specific header set."
        )

    if limited_response:
        recommendations.append(
            "Re-test an accessible 200 OK page when available; access-denied or error responses may not represent normal site headers."
        )
    elif not recommendations:
        recommendations.append("No major recommendations. Current HTTP header configuration follows good security practices.")
    elif not significant_concerns and not limited_response and score >= 7:
        recommendations = ["No major recommendations. Current HTTP header configuration follows good security practices."]

    return min(round(score), 10), enabled, not_observed, informational, recommendations, limited_response


def _status_code_text(status_code: int) -> str:
    return str(status_code)


def _status_label(response: requests.Response) -> str:
    reason = response.reason or ""
    return f"{response.status_code} {reason}".strip()


def analyze_headers(target: str) -> dict:
    url = _normalize_url(target)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if parsed.scheme not in {"http", "https"} or not hostname:
        return {"error": "Please enter a valid domain or URL."}

    if _is_private_or_local(hostname):
        return {"error": "Private, local, or internal addresses are blocked for safety."}

    try:
        session = requests.Session()
        history = []
        current_url = url
        response = None

        for _ in range(8):
            current_host = urlparse(current_url).hostname or ""
            if _is_private_or_local(current_host):
                return {"error": "Redirect to a private, local, or internal address was blocked."}

            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=12,
                headers=REQUEST_HEADERS,
                stream=True,
            )
            response.close()
            history.append(response.url)

            if not response.is_redirect and not response.is_permanent_redirect:
                break

            next_url = response.headers.get("Location")
            if not next_url:
                break
            next_url = requests.compat.urljoin(response.url, next_url)
            next_parsed = urlparse(next_url)
            if next_parsed.scheme not in {"http", "https"}:
                return {"error": "Redirect to an unsupported URL scheme was blocked."}
            next_host = next_parsed.hostname or ""
            if _is_private_or_local(next_host):
                return {"error": "Redirect to a private, local, or internal address was blocked."}
            current_url = next_url
        else:
            return {"error": "Too many redirects. Analysis stopped for safety."}

        if response is None:
            return {"error": "Could not fetch headers."}
    except requests.exceptions.SSLError:
        if parsed.scheme == "https":
            return analyze_headers(url.replace("https://", "http://", 1))
        return {"error": "SSL/TLS connection failed."}
    except requests.exceptions.Timeout:
        if parsed.scheme == "https":
            return analyze_headers(url.replace("https://", "http://", 1))
        return {"error": "Request timed out. Please try again."}
    except requests.exceptions.RequestException as exc:
        if parsed.scheme == "https":
            return analyze_headers(url.replace("https://", "http://", 1))
        return {"error": f"Could not fetch headers: {exc}"}

    headers = response.headers
    cookie_value = _cookie_flags(headers)
    redirects = _redirect_chain(history)
    server_value = headers.get("Server") or ""
    server_version_exposed = _server_version_exposed(server_value)
    score, enabled, not_observed, informational, recommendations, limited_response = _score_headers(
        headers,
        cookie_value,
        response.url,
        server_version_exposed,
        response.status_code,
    )

    rows = {
        "HTTP Status": _status_label(response),
        "Server": headers.get("Server") or "Hidden",
        "Content-Type": headers.get("Content-Type") or "Unknown",
        "Content-Length": _content_length_label(headers),
        "Cache-Control": headers.get("Cache-Control") or "Missing",
        "Strict-Transport-Security": "Present" if headers.get("Strict-Transport-Security") else "Not Observed",
        "Content-Security-Policy": "Present" if headers.get("Content-Security-Policy") else "Not Observed",
        "X-Frame-Options": "Present" if headers.get("X-Frame-Options") else "Not Observed",
        "X-Content-Type-Options": "Present" if headers.get("X-Content-Type-Options") else "Not Observed",
        "Referrer-Policy": "Present" if headers.get("Referrer-Policy") else "Not Observed",
        "Permissions-Policy": "Present" if headers.get("Permissions-Policy") else "Not Observed",
        "Access-Control-Allow-Origin": headers.get("Access-Control-Allow-Origin") or "Not Present",
        "Set-Cookie": cookie_value,
        "Redirects": redirects,
    }

    return {
        "url": response.url,
        "rows": rows,
        "score": score,
        "enabled": enabled,
        "not_observed": not_observed,
        "informational": informational,
        "recommendations": recommendations,
        "server_value": server_value,
        "server_version_exposed": server_version_exposed,
        "cookie_value": cookie_value,
        "redirects": redirects,
        "status_code": response.status_code,
        "limited_response": limited_response,
    }


def _render_table(rows: dict):
    body = ""
    for field, value in rows.items():
        body += (
            f"<tr><td>{html.escape(field)}</td>"
            f"<td>{html.escape(str(value))}</td></tr>"
        )
    st.markdown(f"""
    <table class="meta-table meta-summary-table">
      <thead><tr><th>Header Field</th><th>Result</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """, unsafe_allow_html=True)


def _assessment(score: int) -> str:
    if score >= 9:
        return "Excellent"
    if score >= 7:
        return "Good"
    if score >= 5:
        return "Moderate"
    return "Needs Improvement"


def _render_summary(result: dict):
    enabled = ", ".join(result["enabled"]) if result["enabled"] else "None"
    not_observed = ", ".join(result["not_observed"]) if result["not_observed"] else "None"
    informational_items = list(result["informational"])
    if result["server_value"]:
        server = (
            f"Server information is disclosed ({result['server_value']}); version detail is present."
            if result["server_version_exposed"]
            else f"Server header is present ({result['server_value']}) without obvious version detail."
        )
    else:
        server = "Server header is hidden."
    redirects = "No redirects observed." if result["redirects"] == "None" else "Redirect chain observed and final response headers were analyzed."
    cookies = result["cookie_value"]
    cookie_note = (
        "No cookies were set by the response."
        if cookies == "No Set-Cookie header"
        else f"Cookie flags: {cookies}."
    )
    assessment = _assessment(result["score"])
    scope_note = (
        "Because this was not a 200 OK response, treat the score as a passive snapshot of the received response rather than a complete assessment of the site."
        if result["limited_response"]
        else "Assessment is based on the final response after redirects."
    )
    informational_items.extend([
        server,
        redirects,
        cookie_note,
        scope_note,
        "Header behavior can vary by endpoint, CDN, region, HTTP version, and request headers.",
    ])
    informational = "<br>".join(f"- {html.escape(item)}" for item in informational_items) if informational_items else "- None"
    recommendations = (
        "<br>".join(f"- {html.escape(item)}" for item in result["recommendations"])
        if result["recommendations"]
        else "- No immediate header recommendations based on this passive response."
    )
    assessment_detail = (
        f"{assessment} passive snapshot for this {result['status_code']} response; not a site-wide posture rating."
        if result["limited_response"]
        else f"{assessment} header posture based on passive response headers and transport indicators."
    )

    st.markdown(f"""
    <div class="card">
      <b>Positive Findings:</b><br>
      - Enabled protections observed: {html.escape(enabled)}<br><br>
      <b>Informational Findings:</b><br>
      - Headers not observed in this response: {html.escape(not_observed)}<br>
      {informational}<br><br>
      <b>Recommendations:</b><br>
      {recommendations}<br><br>
      <b>Overall assessment:</b> {assessment_detail}
    </div>
    """, unsafe_allow_html=True)


def render_http_header_analyzer():
    st.subheader("HTTP Header Analyzer")
    st.markdown(
        "Inspect response headers, redirect behavior, cookie flags, and key browser security protections."
    )

    with st.form("http_header_form", clear_on_submit=False):
        target = st.text_input(
            "Domain or URL",
            placeholder="example.com or https://example.com",
            key="http_header_target",
        )
        submitted = st.form_submit_button("Analyze Headers", type="primary", use_container_width=True)

    if submitted:
        if not target.strip():
            st.warning("Please enter a domain or URL.")
            return

        with st.spinner("Fetching HTTP headers..."):
            result = analyze_headers(target)

        if result.get("error"):
            st.error(result["error"])
            return

        st.markdown(f"**Analyzed URL:** {result['url']}")
        _render_table(result["rows"])
        st.metric("Security Headers Score", f"{result['score']} / 10")
        st.markdown("#### Analysis Summary")
        _render_summary(result)
