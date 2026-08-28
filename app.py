import os
import sys
import streamlit as st
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="Sentinel OSINT Platform",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_dotenv()

from utils.helpers import load_css
load_css(os.path.join(os.path.dirname(__file__), "assets", "style.css"))

# Force black text on all solid-blue primary buttons (overrides Streamlit's span colour injection)
st.markdown("""
<style>
/*  Solid blue primary button text  black  */
button[data-testid="stBaseButton-primary"] p,
button[data-testid="stBaseButton-primary"] span,
button[data-testid="stBaseButton-primary"] div,
button[data-testid="stBaseButton-primary"] * {
    color: #000000 !important;
}

/*  All input / textarea / select text  black  */
input, textarea,
.stTextInput input,
.stNumberInput input,
input[type="text"],
input[type="number"],
input[type="password"],
div[data-baseweb="input"] input,
div[data-baseweb="textarea"] textarea,
div[data-baseweb="select"] [class*="singleValue"],
div[data-baseweb="select"] [class*="placeholder"],
div[data-baseweb="select"] span,
.stSelectbox span {
    color: #000000 !important;
}

div[data-baseweb="select"],
div[data-baseweb="select"] *,
div[role="listbox"],
div[role="option"],
div[role="option"] * {
    color: #000000 !important;
    opacity: 1 !important;
}

div[data-baseweb="select"] [class*="singleValue"],
div[data-baseweb="select"] [class*="placeholder"] {
    color: #000000 !important;
}

div[role="listbox"] {
    background: #f4f5f7 !important;
}

/*  SSL card: .green / .yellow / .red span colors must not be overridden  */
.card span.green  { color: #1A7A52 !important; font-weight: 600 !important; }
.card span.yellow { color: #E87B00 !important; font-weight: 600 !important; }
.card span.red    { color: #C0392B !important; font-weight: 600 !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
input, textarea,
.stTextInput input,
.stNumberInput input,
input[type="text"],
input[type="number"],
input[type="password"],
div[data-baseweb="input"] input,
div[data-baseweb="textarea"] textarea {
    color: #f8fafc !important;
}

div[data-baseweb="select"] [class*="singleValue"],
div[data-baseweb="select"] [class*="placeholder"],
div[data-baseweb="select"] span,
.stSelectbox span,
div[data-baseweb="select"] *,
.stSelectbox * {
    color: #e6edf7 !important;
}

div[role="listbox"],
div[role="option"],
div[role="option"] * {
    background: #101c2f !important;
    color: #e6edf7 !important;
}
</style>
""", unsafe_allow_html=True)


def render_login_page():
    left_col, form_col = st.columns([1.08, 1], gap="large")
    with left_col:
        st.markdown("""
<section class="login-visual">
    <div class="brand-lockup">
      <div class="brand-mark">S</div>
      <div>
        <div class="brand-name">Sentinel OSINT</div>
        <div class="brand-kicker">Enterprise intelligence workspace</div>
      </div>
    </div>
    <div class="login-copy">
      <span class="eyebrow">Unified exposure intelligence</span>
      <h1>Sentinel OSINT Command Center</h1>
      <p>Investigate domains, infrastructure, identities, and risk signals from a focused analyst workspace.</p>
    </div>
  </section>
""", unsafe_allow_html=True)

    with form_col:
        st.markdown("""
<div class="login-panel-copy">
  <span class="eyebrow">Secure Access</span>
  <h2>Sign in to continue</h2>
  <p>Use the provided admin credentials to open the dashboard.</p>
</div>
""", unsafe_allow_html=True)
        with st.form("login_form"):
            login_email = st.text_input("Email address", placeholder="admin@gmail.com", key="login_email")
            show_password = st.checkbox("Show password", key="login_show_password")
            login_password = st.text_input(
                "Password",
                placeholder="admin123",
                type="default" if show_password else "password",
                key="login_password"
            )
            option_col, link_col = st.columns([1, 1])
            with option_col:
                st.checkbox("Remember me", key="login_remember")
            with link_col:
                st.markdown("<a class='forgot-link' href='#'>Forgot password?</a>", unsafe_allow_html=True)
            submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)

        if submitted:
            email = login_email.strip()
            password = login_password
            if email == "admin@gmail.com" and password == "admin123":
                st.session_state.app_logged_in = True
                st.rerun()
            else:
                st.error("Invalid credentials. Use admin@gmail.com / admin123.")

        st.markdown(
            "<div class='login-footnote'>Demo credentials: admin@gmail.com / admin123</div>",
            unsafe_allow_html=True
        )


if "app_logged_in" not in st.session_state:
    st.session_state.app_logged_in = False

if not st.session_state.app_logged_in:
    render_login_page()
    st.stop()

st.components.v1.html("""
<script>
const resetScroll = () => {
  const main = window.parent.document.querySelector('.stMain');
  if (main) {
    main.scrollTo(0, 0);
    main.scrollTop = 0;
  }
  window.parent.scrollTo(0, 0);
};
[0, 60, 180, 420, 900].forEach(delay => setTimeout(resetScroll, delay));
</script>
""", height=0)

_, logout_col = st.columns([5.5, 1])
with logout_col:
    if st.button("Sign out", key="logout_btn", use_container_width=True):
        st.session_state.app_logged_in = False
        st.session_state.login_password = ""
        st.rerun()

from utils.helpers               import detect_input_type
from modules.reputation          import (fetch_vt_domain, fetch_vt_ip,
                                         render_ip_reputation, render_domain_reputation)
from modules.ssl_cert            import render_ssl_info
from modules.dns_intel           import render_dns_domain, render_dns_ip
from modules.subdomains          import (render_subdomains, render_subdomains_from_ip)
from modules.typosquatting       import render_typosquatting
from modules.sherlock_hunt       import render_sherlock
from modules.hash_tool           import render_hash_tool
from modules.network_graph       import render_network_graph
from modules.cyber_news          import render_cyber_news
from modules.metadata_inspector  import render_metadata_inspector
from modules.http_headers        import render_http_header_analyzer

VT_API_KEY        = os.getenv("VT_API_KEY")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIEWDNS_API_KEY   = os.getenv("VIEWDNS_API_KEY")

for key, val in [
    ("sherlock_results",        []),
    ("sherlock_scanning",       False),
    ("sherlock_username",       None),
    ("sherlock_stop_requested", False),
    ("active_filter",           "All"),
    ("pwd_active",              "generator"),
    ("ng_subs",                 True),
    ("ng_ports",                True),
    ("ng_threat",               True),
]:
    if key not in st.session_state:
        st.session_state[key] = val

NAV_TABS = [
    "All",
    "IP/Domain Reputation",
    "TLS / SSL Certificate Intelligence",
    "DNS Intelligence",
    "Subdomain Discovery",
    "Typosquatting Analysis",
    "Network Graph",
    "Username Hunt",
    "Breach Check",
    "Hash and Integrity",
    "Password Security",
    "Metadata Inspector",
    "HTTP Header Analyzer",
    "Security Support Hub",
    "Cyber News",
]

# 
# HEADER ROW - title left, logo top-right (original size)
# 
col_title, col_logo = st.columns([4, 1])

with col_title:
    st.markdown("""
<div class='osint-header'>
    <h1>Cyber Intelligence Operations Console</h1>
    <p>Monitor reputation, infrastructure exposure, DNS signals, identity traces, password risk, and security response resources from one analyst workspace.</p>
</div>
""", unsafe_allow_html=True)

with col_logo:
    logo_path = os.path.join(os.path.dirname(__file__), "download-removebg-preview.png")
    if os.path.exists(logo_path):
        st.image(logo_path, width=126)

# 
# CUSTOM NAV FILTER PILLS - wraps to 2 lines, equal spacing,
# full label always visible. st.pills handles layout natively.
# 
selected_pill = st.pills(
    "Filter",
    NAV_TABS,
    default=st.session_state.active_filter,
    key="nav_pills",
    label_visibility="collapsed",
)
if selected_pill and selected_pill != st.session_state.active_filter:
    st.session_state.active_filter = selected_pill
if selected_pill:
    st.session_state.active_filter = selected_pill

selected_filter = st.session_state.active_filter

active_pill_label = selected_filter.replace("'", "\\'")
st.markdown("""
<script>
(function applyActivePill() {{
    const label = '{0}';
    const container = document.querySelector('[data-testid="stPillsContainer"]');
    if (!container) {{ setTimeout(applyActivePill, 120); return; }}
    const normalize = text => text.replace(/\\s+/g, ' ').trim();
    const targetLabel = normalize(label);
    container.querySelectorAll('button').forEach(btn => {{
        const isActive = normalize(btn.innerText) === targetLabel;
        btn.classList.toggle('copilot-selected-pill', isActive);
    }});
}})();
</script>
""".format(active_pill_label), unsafe_allow_html=True)

st.markdown("""
<div class="ops-strip">
  <div><span>Coverage</span><strong>15 modules</strong></div>
  <div><span>Workflow</span><strong>Recon to response</strong></div>
  <div><span>Console</span><strong>Analyst-grade UI</strong></div>
</div>
""", unsafe_allow_html=True)


def should_show(tool_name: str) -> bool:
    return selected_filter in ("All", tool_name)


# 
# STANDALONE TOOLS
# 

if selected_filter == "Breach Check":
    import urllib.parse

    st.subheader("Breach Check - Have I Been Pwned")
    st.markdown(
        "<div class='card'>Check if your email address has been exposed in a known data breach. "
        "Enter your email below and click the button to check on <b>Have I Been Pwned</b>.</div>",
        unsafe_allow_html=True
    )

    with st.form("breach_check_form", clear_on_submit=False):
        breach_email = st.text_input(
            "Email address",
            placeholder="youremail@example.com",
            key="breach_email_input"
        )
        breach_submitted = st.form_submit_button("Check for Breaches", type="primary", use_container_width=True)

    if breach_submitted:
        email_val = breach_email.strip() if breach_email else ""
        if not email_val or "@" not in email_val:
            st.warning("Please enter a valid email address.")
        else:
            encoded_email = urllib.parse.quote(email_val, safe="")
            hibp_url = f"https://haveibeenpwned.com/account/{encoded_email}"
            # Open HIBP in a new tab - app stays open in the current tab
            st.components.v1.html(
                f"<script>window.open('{hibp_url}', '_blank');</script>",
                height=0,
            )
            st.markdown(
                f"<div style='background:rgba(74,180,255,0.08);border:1.5px solid #4AB4FF;"
                f"border-radius:10px;padding:18px 22px;margin:12px 0;text-align:center;'>"
                f"<span style='color:#4AB4FF;font-weight:700;font-size:1.05rem;'>Opening Have I Been Pwned in a new tab...</span><br>"
                f"<span style='color:#4A6A8A;font-size:0.9rem;margin-top:6px;display:block;'>"
                f"Checking <b style='color:#F8FAFF;'>{email_val}</b> on HIBP.<br>"
                f"If the tab did not open, "
                f"<a href='{hibp_url}' target='_blank' style='color:#4AB4FF;'>click here</a>.</span>"
                f"</div>",
                unsafe_allow_html=True
            )

    st.markdown(
        "<div style='margin-top:18px;font-size:0.8rem;color:#4A6A8A;line-height:1.9;'>"
        "<b style='color:#0D3380;'>About Have I Been Pwned</b><br>"
        "Free service by security researcher Troy Hunt. Monitors billions of breached credentials "
        "across major breaches (LinkedIn, Adobe, etc.). Your email is never stored or shared."
        "</div>",
        unsafe_allow_html=True
    )
    st.stop()

if selected_filter == "Hash and Integrity":
    render_hash_tool()
    st.stop()

if selected_filter == "Password Security":
    from modules.password_security import render_password_security
    render_password_security()
    st.stop()

if selected_filter == "Metadata Inspector":
    render_metadata_inspector()
    st.stop()

if selected_filter == "HTTP Header Analyzer":
    render_http_header_analyzer()
    st.stop()

if selected_filter == "Security Support Hub":
    from modules.security_hub import render_security_hub
    render_security_hub()
    st.stop()

if selected_filter == "Cyber News":
    render_cyber_news()
    st.stop()


# 
# QUERY-BASED TOOLS
# 

#  Contextual display options (left-aligned) 
if selected_filter in ("All", "Subdomain Discovery", "Typosquatting Analysis"):
    if selected_filter == "All":
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("##### Subdomain Display")
            sub_limit = st.selectbox("Number of subdomains", [15, 50, "All"], index=0, key="sub_limit")
        with col2:
            st.markdown("##### Typosquatting Display")
            typo_limit = st.selectbox("Number of typo domains", [10, 25, 50, "All"], index=0, key="typo_limit")
    elif selected_filter == "Subdomain Discovery":
        col1, _spacer = st.columns([1, 1])
        with col1:
            st.markdown("##### Subdomain Display")
            sub_limit = st.selectbox("Number of subdomains", [15, 50, "All"], index=0, key="sub_limit")
        typo_limit = 10
    else:
        col1, _spacer = st.columns([1, 1])
        with col1:
            st.markdown("##### Typosquatting Display")
            typo_limit = st.selectbox("Number of typo domains", [10, 25, 50, "All"], index=0, key="typo_limit")
        sub_limit = 15
else:
    sub_limit  = 15
    typo_limit = 10

#  Context-aware query label 
QUERY_LABELS = {
    "All": (
        "IP / Domain / URL / Email / Username",
        "e.g.  8.8.8.8  -  google.com  -  https://example.com  -  user@example.com  -  john_doe"
    ),
    "IP/Domain Reputation": (
        "IP Address or Domain",
        "e.g.  8.8.8.8  or  google.com"
    ),
    "TLS / SSL Certificate Intelligence": (
        "IP Address or Domain",
        "e.g.  8.8.8.8  or  example.com"
    ),
    "DNS Intelligence": (
        "IP Address or Domain",
        "e.g.  8.8.8.8  or  example.com"
    ),
    "Subdomain Discovery": (
        "Domain",
        "e.g.  example.com"
    ),
    "Typosquatting Analysis": (
        "Domain",
        "e.g.  example.com"
    ),
    "Username Hunt": (
        "Username",
        "e.g.  john_doe"
    ),
}

q_label, q_placeholder = QUERY_LABELS.get(
    selected_filter,
    ("IP / Domain / URL / Email / Username",
     "e.g.  8.8.8.8  -  google.com  -  https://example.com")
)

#  Network Graph options - shown before search so user can configure first 
if selected_filter in ("All", "Network Graph"):
    with st.expander(" Network Graph Options", expanded=(selected_filter == "Network Graph")):
        gc1, gc2, gc3 = st.columns(3)
        gc1.toggle("Include subdomains",       key="ng_subs")
        gc2.toggle("Include open ports (Shodan)", key="ng_ports")
        gc3.toggle("Include threat tags",      key="ng_threat")

#  API Key Status 
with st.expander("API Key Status"):
    st.markdown(f"""
    - **VirusTotal:**  {'Configured' if VT_API_KEY        else 'Missing'}
    - **Shodan:**      {'Configured' if SHODAN_API_KEY     else 'Missing'}
    - **AbuseIPDB:**   {'Configured' if ABUSEIPDB_API_KEY  else 'Missing'}
    - **ViewDNS:**     {'Configured' if VIEWDNS_API_KEY    else 'Missing'}
    - **Sherlock:**    Local install (no key needed)
    """)

query = st.session_state.get("main_query_input", "")

if not query:
    st.markdown("""
<div class="empty-state-panel">
  <span class="empty-state-kicker">Ready for investigation</span>
  <strong>Select a module, enter an indicator, and run a search.</strong>
  <p>Results, scan details, and intelligence summaries will appear here after the first query.</p>
</div>
""", unsafe_allow_html=True)

with st.form("main_search_form", clear_on_submit=False):
    query = st.text_input(q_label, placeholder=q_placeholder, key="main_query_input")
    search_clicked = st.form_submit_button("Search", use_container_width=True, type="primary")

if search_clicked:
    if not query:
        st.warning("Please enter a value to search.")
    else:
        input_type = detect_input_type(query)

        if input_type == "UNKNOWN":
            st.error("Invalid input. Please enter a valid IP, domain, URL, email, or username.")

        elif input_type == "IP":
            st.markdown(f"""
            <style>
            .ip-detected-box {{ color: #000000 !important; }}
            .ip-detected-box * {{ color: #000000 !important; }}
            .ip-detected-box span {{ color: #000000 !important; }}
            .ip-detected-box b {{ color: #000000 !important; }}
            </style>
            <div class='ip-detected-box' style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;font-size:0.92rem;margin-bottom:8px;'>
                <span style='color:#000000;'>IP address detected: </span><b style='color:#000000;font-weight:700;'>{query}</b>
            </div>
            """, unsafe_allow_html=True)

            if should_show("IP/Domain Reputation"):
                render_ip_reputation(query)

            if should_show("TLS / SSL Certificate Intelligence"):
                with st.spinner("Fetching SSL certificate data..."):
                    vt_ssl = fetch_vt_ip(query)
                if vt_ssl and "data" in vt_ssl:
                    render_ssl_info(vt_ssl["data"]["attributes"])

            if should_show("DNS Intelligence") and VIEWDNS_API_KEY:
                render_dns_ip(query)

            if should_show("Subdomain Discovery"):
                with st.spinner("Fetching VirusTotal resolutions..."):
                    vt2 = fetch_vt_ip(query)
                render_subdomains_from_ip(query, vt2, sub_limit)

            if should_show("Network Graph"):
                render_network_graph(query)

        elif input_type == "DOMAIN" or input_type.startswith("DOMAIN:"):
            if input_type.startswith("DOMAIN:"):
                domain_to_check = input_type.split(":", 1)[1]
                st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>URL detected: **{query}**</div>", unsafe_allow_html=True)
                st.info(f"Analysing domain: **{domain_to_check}**")
            else:
                domain_to_check = query
                st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>Domain detected: **{query}**</div>", unsafe_allow_html=True)

            if should_show("IP/Domain Reputation"):
                render_domain_reputation(domain_to_check)

            if should_show("TLS / SSL Certificate Intelligence"):
                with st.spinner("Fetching SSL certificate data..."):
                    vt_ssl = fetch_vt_domain(domain_to_check)
                if vt_ssl and "data" in vt_ssl:
                    render_ssl_info(vt_ssl["data"]["attributes"])

            if should_show("DNS Intelligence"):
                render_dns_domain(
                    domain_to_check,
                    include_viewdns_details=(selected_filter == "DNS Intelligence")
                )

            if should_show("Subdomain Discovery"):
                render_subdomains(domain_to_check, sub_limit)

            if should_show("Typosquatting Analysis"):
                render_typosquatting(domain_to_check, typo_limit)

            if should_show("Network Graph"):
                render_network_graph(domain_to_check)

        elif input_type == "EMAIL":
            parts = query.strip().split("@")
            if len(parts) < 2 or not parts[1]:
                st.error("Invalid email address. Please include the domain part (e.g. user@example.com)")
                st.stop()
            email_domain = parts[1].lower()
            st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>Email detected: **{query}**</div>", unsafe_allow_html=True)
            st.info(f"Analysing domain: **{email_domain}**")

            if should_show("IP/Domain Reputation"):
                render_domain_reputation(email_domain)

            if should_show("TLS / SSL Certificate Intelligence"):
                with st.spinner("Fetching SSL certificate data..."):
                    vt_ssl = fetch_vt_domain(email_domain)
                if vt_ssl and "data" in vt_ssl:
                    render_ssl_info(vt_ssl["data"]["attributes"])

            if should_show("DNS Intelligence"):
                render_dns_domain(
                    email_domain,
                    include_viewdns_details=(selected_filter == "DNS Intelligence")
                )

            if should_show("Subdomain Discovery"):
                render_subdomains(email_domain, sub_limit)

            if should_show("Typosquatting Analysis"):
                render_typosquatting(email_domain, typo_limit)

            if should_show("Network Graph"):
                render_network_graph(email_domain)

        elif input_type == "USERNAME":
            st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>Username detected: **{query}**</div>", unsafe_allow_html=True)
            if should_show("Username Hunt"):
                render_sherlock(query)

# 
# FOOTER
# 
st.markdown("""
<div class="caution-footer">
<span>DISCLAIMER</span> - This tool is intended for
<b>authorised security research and educational purposes only</b>.<br>
Misuse of this platform may violate applicable laws and regulations.
Always obtain proper authorisation before scanning any target.<br>
<i>Built for OSINT researchers - Use responsibly and ethically</i>
</div>
""", unsafe_allow_html=True)
