import json
import time
import concurrent.futures
import streamlit as st
import requests
from typing import List


#  Source 1: crt.sh 
def _fetch_crtsh(domain: str, timeout: int = 10) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                         timeout=timeout)
        if r.status_code == 200:
            subs = set()
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name and name:
                        subs.add(name.lower())
            return sorted(subs)
    except Exception:
        pass
    return []


#  Source 2: HackerTarget 
def _fetch_hackertarget(domain: str, timeout: int = 10) -> List[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                         timeout=timeout)
        if r.status_code == 200 and "error" not in r.text.lower()[:40]:
            subs = set()
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts:
                    name = parts[0].strip()
                    if domain in name and name:
                        subs.add(name.lower())
            return sorted(subs)
    except Exception:
        pass
    return []


#  Source 3: RapidDNS 
def _fetch_rapiddns(domain: str, timeout: int = 10) -> List[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                         timeout=timeout)
        if r.status_code == 200:
            import re
            matches = re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text)
            subs = {m.lower() for m in matches if domain in m}
            return sorted(subs)
    except Exception:
        pass
    return []


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_subdomains(domain: str) -> List[str]:
    """Query passive sources in parallel and return combined unique results."""
    sources = [_fetch_crtsh, _fetch_hackertarget, _fetch_rapiddns]
    combined = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = [executor.submit(source, domain) for source in sources]
        try:
            for future in concurrent.futures.as_completed(futures, timeout=12):
                combined.update(future.result() or [])
        except concurrent.futures.TimeoutError:
            pass

    return sorted(combined)


def render_subdomains(domain: str, limit):
    st.subheader("Subdomain Discovery (Passive OSINT)")
    with st.spinner("Fetching subdomains from Certificate Transparency..."):
        subs = fetch_subdomains(domain)

    if subs:
        lim = len(subs) if limit == "All" else limit
        st.markdown(
            f"<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;"
            f"border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;"
            f"color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>"
            f" Found {len(subs)} subdomains</div>",
            unsafe_allow_html=True
        )
        for s in subs[:lim]:
            st.markdown(f"<div class='engine'>- {s}</div>",
                        unsafe_allow_html=True)
        if len(subs) > lim:
            st.info(f" Showing {lim} of {len(subs)}. Change limit above.")
    else:
        st.markdown(
            "<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;"
            "border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;"
            "color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>"
            " No subdomains found in public CT logs for this domain.</div>",
            unsafe_allow_html=True
        )


def render_subdomains_from_ip(ip: str, vt_data: dict, limit):
    if vt_data and "data" in vt_data:
        resolutions = vt_data["data"]["attributes"].get("resolutions", [])
        root_domains = sorted(
            {r.get("host_name") for r in resolutions if r.get("host_name")}
        )
        if root_domains:
            st.subheader("Related Domains & Subdomains")
            shown = 0
            max_d = float("inf") if limit == "All" else limit
            for dom in root_domains[:5]:
                with st.spinner(f"Fetching subdomains for {dom}..."):
                    subs = fetch_subdomains(dom)
                if subs:
                    st.markdown(f"**Domain: {dom}**")
                    for s in subs:
                        if shown >= max_d:
                            break
                        st.markdown(f"<div class='engine'>- {s}</div>",
                                    unsafe_allow_html=True)
                        shown += 1
                    if shown >= max_d:
                        break
