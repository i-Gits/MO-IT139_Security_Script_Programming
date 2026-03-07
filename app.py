import streamlit as st
import sys
import os
import nltk
import pandas as pd
import plotly.graph_objects as go
import tempfile
import time
import random
import hashlib
import threading
from st_keyup import st_keyup
from scapy.all import wrpcap
from streamlit_option_menu import option_menu

# --- 1. SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'src'))

try:
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('words')

# import features
from features.password_strength import evaluate_password_strength
from features.password_generator import generate_password, hash_password, save_to_file
from features.webform_validator import validate_and_sanitize_form
from features.network_port_scanner import PORT_PRESETS, COMMON_PORTS_BY_CATEGORY, validate_host, validate_port_range, scan_port_range, get_service_name
from features.network_traffic_analyzer import get_scapy_status, validate_filter, start_packet_capture

# --- 2. CONFIG ---
st.set_page_config(
    page_title="PASSECURIST",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 3. STYLING ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

    /* Smooth Fade-In Animation */
    [data-testid="stMainBlockContainer"] { animation: fadeIn 0.4s ease-out; }
    @keyframes fadeIn {
        0% { opacity: 0; transform: translateY(10px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div,
    .stNumberInput > div > div > input { background-color: #1e293b; color: white; border: 1px solid #475569; border-radius: 6px; font-size: 14px; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; margin-bottom: 20px; }
    .stTabs [data-baseweb="tab"] { height: 40px; white-space: pre-wrap; background-color: transparent; border-radius: 6px; color: #94a3b8; font-weight: 600; padding: 0 16px; border: 1px solid transparent; }
    .stTabs [aria-selected="true"] { background-color: #1e293b !important; color: #38bdf8 !important; border: 1px solid #334155 !important; }
    .stButton > button { background-color: #38bdf8; color: #0f172a; font-weight: 900; border-radius: 6px; border: none; padding: 0.5rem 1rem; width: 100%; font-size: 14px; }
    .stButton > button:hover { background-color: #0ea5e9; color: white; }
    .stProgress > div > div > div > div { background-color: #38bdf8; }

    .stat-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155; border-radius: 10px;
        padding: 16px 20px; text-align: center;
        position: relative; overflow: hidden;
        display: flex; flex-direction: column;
        justify-content: center; align-items: center;
        min-height: 90px; height: 90px; box-sizing: border-box;
    }
    .stat-card::before {
        content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
        background: linear-gradient(90deg, #38bdf8, #0ea5e9);
    }
    .stat-number { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; line-height: 1.1; margin: 4px 0; }
    .stat-label { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: #64748b; margin-top: 2px; }
    .stat-open { color: #22c55e; }
    .stat-closed { color: #ef4444; }
    .stat-total { color: #38bdf8; }
    .stat-neutral { color: #e2e8f0; }

    .viz-section-header {
        font-size: 0.7rem; font-weight: 700; letter-spacing: 0.18em;
        text-transform: uppercase; color: #475569;
        padding: 6px 0 10px 0; border-bottom: 1px solid #1e293b; margin-bottom: 16px;
    }

    /* Traceroute controls bar */
    .tr-controls {
        background: #0d1829;
        border: 1px solid #1e3a5f;
        border-radius: 10px 10px 0 0;
        padding: 12px 18px;
        display: flex; align-items: center; gap: 12px;
        border-bottom: 1px solid #0f2744;
    }
    .tr-badge {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.65rem; font-weight: 700; letter-spacing: 0.15em;
        text-transform: uppercase; color: #38bdf8;
        background: rgba(56,189,248,0.08);
        border: 1px solid rgba(56,189,248,0.2);
        padding: 3px 10px; border-radius: 20px;
    }
    /* Traceroute graph container */
    .tr-graph-wrap {
        background: linear-gradient(180deg, #0a1628 0%, #0d1e35 100%);
        border: 1px solid #1e3a5f;
        border-top: none;
        border-radius: 0 0 10px 10px;
        padding: 4px 0 0 0;
        position: relative;
    }
    /* Legend pills */
    .tr-legend {
        display: flex; gap: 16px; padding: 10px 18px 0 18px; flex-wrap: wrap;
    }
    .tr-legend-item {
        display: flex; align-items: center; gap: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.65rem; color: #475569;
    }
    .tr-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0; }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# --- 4. HEADER ---
st.title("🛡️ PASSECURIST")
st.markdown("##### A Comprehensive Security Toolkit!")
st.markdown("###### Made by C. Encillo, H. Tantoco, J. Delas Armas, and M. Samaniego.")
st.markdown("---")

# --- 5. PLOTLY THEME ---
PLOTLY_LAYOUT = dict(
    paper_bgcolor='rgba(0,0,0,0)',
    plot_bgcolor='rgba(0,0,0,0)',
    font=dict(color='#94a3b8', family='JetBrains Mono, monospace', size=11),
    margin=dict(l=10, r=10, t=36, b=10),
    legend=dict(bgcolor='rgba(15,23,42,0.7)', bordercolor='#334155', borderwidth=1, font=dict(size=11))
)

ACCENT_COLORS = ['#38bdf8', '#22c55e', '#f59e0b', '#ef4444', '#a78bfa', '#fb923c', '#34d399', '#f472b6']

# --- HELPER: category lookup ---
def build_category_lookup():
    lookup = {}
    for cat, entries in COMMON_PORTS_BY_CATEGORY.items():
        for port_str, _ in entries:
            for chunk in port_str.replace('/', ',').split(','):
                chunk = chunk.strip()
                if chunk.isdigit():
                    lookup[int(chunk)] = cat
    return lookup

PORT_CATEGORY_MAP = build_category_lookup()

def get_port_category(port):
    return PORT_CATEGORY_MAP.get(port, "Other / Dynamic")


# ==========================================
# TRACEROUTE IMPLEMENTATION
# ==========================================

def _get_gateway_mac() -> tuple:
    """
    Detect active network interface and gateway MAC address.

    Works on Windows, macOS, and Linux.
    Windows uses 'route print', macOS uses 'route -n get default', Linux skips
    to the subnet .1 guess. All three fall back to 'arp -a' for the MAC lookup.

    Returns (iface, gw_mac) or (None, None) on failure.
    """
    try:
        from scapy.all import get_if_list, get_if_addr, ARP, Ether, srp
        import subprocess, ipaddress, platform

        os_name = platform.system()  # 'Windows', 'Darwin' (macOS), or 'Linux'

        # --- Step 1: find active interface (real IP, not link-local) ---
        # Works on all platforms — Scapy's get_if_list() is cross-platform.
        active_iface = None
        for iface in get_if_list():
            ip = get_if_addr(iface)
            try:
                parsed = ipaddress.ip_address(ip)
                if not parsed.is_loopback and not parsed.is_link_local and ip != "0.0.0.0":
                    active_iface = iface
                    break
            except Exception:
                continue

        if not active_iface:
            return None, None

        # --- Step 2: get gateway IP (OS-specific commands) ---
        gw_ip = None
        try:
            if os_name == "Windows":
                out = subprocess.check_output("route print 0.0.0.0", shell=True).decode(errors="ignore")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        candidate = parts[2]
                        try:
                            ipaddress.ip_address(candidate)
                            gw_ip = candidate
                            break
                        except ValueError:
                            continue

            elif os_name == "Darwin":  # macOS
                # 'route -n get default' outputs a line like: "gateway: 192.168.1.1"
                out = subprocess.check_output(["route", "-n", "get", "default"]).decode(errors="ignore")
                for line in out.splitlines():
                    if "gateway:" in line:
                        candidate = line.split("gateway:")[-1].strip()
                        try:
                            ipaddress.ip_address(candidate)
                            gw_ip = candidate
                            break
                        except ValueError:
                            continue
        except Exception:
            pass

        # --- Step 3: fallback — guess gateway as x.x.x.1 on same subnet ---
        if not gw_ip:
            try:
                my_ip = get_if_addr(active_iface)
                prefix = ".".join(my_ip.split(".")[:3])
                gw_ip = prefix + ".1"
            except Exception:
                pass

        if not gw_ip:
            return None, None

        # --- Step 4: get MAC from arp cache first (no packet needed) ---
        # 'arp -a' works on Windows, macOS, and most Linux distros.
        try:
            out = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
            for line in out.splitlines():
                if gw_ip in line:
                    parts = line.split()
                    for part in parts:
                        # Match MAC format xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx
                        if len(part) == 17 and (part.count("-") == 5 or part.count(":") == 5):
                            gw_mac = part.replace("-", ":")
                            return active_iface, gw_mac
        except Exception:
            pass

        # --- Step 5: ARP request as last resort ---
        # Sends a broadcast ARP packet to discover the gateway MAC directly.
        # Requires root/admin on all platforms.
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
            iface=active_iface, timeout=3, verbose=0
        )
        if ans:
            gw_mac = ans[0][1].hwsrc
            return active_iface, gw_mac

        return None, None

    except Exception:
        return None, None


def run_scapy_traceroute(target: str, min_ttl: int = 1, max_ttl: int = 30, timeout: int = 3) -> list:
    """
    Traceroute via Scapy using Ether/srp1 with auto-detected gateway MAC.

    Uses Ether layer + srp1() instead of sr1() to correctly route packets
    on Windows where Scapy cannot resolve ARP automatically.

    min_ttl: first TTL to probe (default 1 = own gateway)
    max_ttl: upper bound on hops before giving up (default 30)

    """
    try:
        from scapy.all import IP, ICMP, Ether, srp1, conf
        import socket
        conf.verb = 0

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return [{"error": f"Cannot resolve host: {target}"}]

        # Auto-detect interface and gateway MAC
        active_iface, gw_mac = _get_gateway_mac()
        if not active_iface or not gw_mac:
            return [{"error": "Could not detect gateway MAC. Check network connection."}]

        conf.iface = active_iface

        hops = []
        for ttl in range(min_ttl, max_ttl + 1):
            pkt = Ether(dst=gw_mac) / IP(dst=target_ip, ttl=ttl) / ICMP()
            t0 = time.time()
            reply = srp1(pkt, timeout=timeout, verbose=0)
            rtt_ms = round((time.time() - t0) * 1000, 2)

            if reply is None or not reply.haslayer(IP):
                hops.append({
                    "ttl": ttl, "ip": "*", "hostname": "*",
                    "rtt_ms": None, "icmp_type": None,
                    "is_target": False, "responded": False,
                })
            else:
                hop_ip = reply[IP].src
                icmp_type = reply.getlayer("ICMP").type if reply.haslayer("ICMP") else None
                is_target = (hop_ip == target_ip)
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except Exception:
                    hostname = hop_ip
                hops.append({
                    "ttl": ttl, "ip": hop_ip, "hostname": hostname,
                    "rtt_ms": rtt_ms, "icmp_type": icmp_type,
                    "is_target": is_target, "responded": True,
                })
                if is_target:
                    break

        return hops
    except Exception as e:
        return [{"error": str(e)}]


def _bezier_points(x0, y0, x1, y1, n=30):
    """Return n points along a quadratic Bezier curve between two nodes."""
    cx = (x0 + x1) / 2
    cy = (y0 + y1) / 2 + abs(x1 - x0) * 0.18  # soft upward bow
    pts_x, pts_y = [], []
    for i in range(n + 1):
        t = i / n
        bx = (1-t)**2 * x0 + 2*(1-t)*t * cx + t**2 * x1
        by = (1-t)**2 * y0 + 2*(1-t)*t * cy + t**2 * y1
        pts_x.append(bx); pts_y.append(by)
    return pts_x, pts_y


def build_traceroute_graph(hops: list, target_host: str) -> go.Figure:
    """
    NmapGUI-like traceroute graph (via Plotly)

    Node colour coding (matches NMapGUI):
      Cyan  (#38bdf8) — origin / You
      Green (#22c55e) — target host (reached)
      Blue  (#3b82f6) — intermediate hops that responded
      Grey  (#334155) — hops that did NOT respond (* * *)
    """
    valid_hops = [h for h in hops if h.get("responded", False)]
    total = len(valid_hops)
    if total == 0:
        return None

    # --- Positions ---
    # NMapGUI scatters nodes in a left-to-right flow 
    # Uses seeded deterministic offset so the graph is stable between reruns
    positions = []
    x_step = 10.0 / max(total - 1, 1)
    for i, hop in enumerate(valid_hops):
        base_x = i * x_step
        # deterministic jitter seeded on IP so same host always lands in same spot
        seed = int(hashlib.md5(hop["ip"].encode()).hexdigest()[:6], 16)
        rng  = random.Random(seed)
        jitter_x = rng.uniform(-x_step * 0.3, x_step * 0.3) if 0 < i < total - 1 else 0
        jitter_y = rng.uniform(-1.8, 1.8) if 0 < i < total - 1 else 0
        px = base_x + jitter_x
        py = jitter_y
        hop["_x"] = px; hop["_y"] = py
        positions.append((px, py))

    # --- Bezier edge traces ---
    traces = []
    for i in range(len(valid_hops) - 1):
        h0, h1 = valid_hops[i], valid_hops[i+1]
        bx, by = _bezier_points(h0["_x"], h0["_y"], h1["_x"], h1["_y"])
        traces.append(go.Scatter(
            x=bx + [None], y=by + [None],
            mode='lines',
            line=dict(color='rgba(30,74,107,0.9)', width=1.5),
            hoverinfo='none', showlegend=False
        ))

    # --- Glow halo (shadow circle, drawn first / behind nodes) ---
    glow_x, glow_y, glow_colors, glow_sizes = [], [], [], []
    for i, hop in enumerate(valid_hops):
        is_origin = (i == 0)
        is_target = hop.get("is_target", False)
        if is_origin:
            gc = "rgba(56,189,248,0.18)"
        elif is_target:
            gc = "rgba(34,197,94,0.18)"
        else:
            gc = "rgba(59,130,246,0.12)"
        glow_x.append(hop["_x"]); glow_y.append(hop["_y"])
        glow_colors.append(gc); glow_sizes.append(30)

    traces.append(go.Scatter(
        x=glow_x, y=glow_y,
        mode='markers',
        marker=dict(color=glow_colors, size=glow_sizes, line=dict(width=0)),
        hoverinfo='none', showlegend=False
    ))

    # --- Main node trace ---
    n_x, n_y, n_colors, n_sizes, n_borders, n_texts, n_hovers = [], [], [], [], [], [], []

    for i, hop in enumerate(valid_hops):
        is_origin = (i == 0)
        is_target = hop.get("is_target", False)
        rtt_str   = f"{hop['rtt_ms']} ms" if hop.get("rtt_ms") else "—"
        ip        = hop["ip"]
        hostname  = hop.get("hostname", ip)
        icmp_t    = hop.get("icmp_type")
        icmp_str  = {0: "Echo Reply", 11: "Time Exceeded"}.get(icmp_t, str(icmp_t)) if icmp_t is not None else "—"

        if is_origin:
            color, sz, border = "#38bdf8", 16, "#0ea5e9"
            label = "You\n" + ip
        elif is_target:
            color, sz, border = "#22c55e", 20, "#16a34a"
            label = ip
        else:
            color, sz, border = "#3b82f6", 12, "#2563eb"
            label = ip

        # Tooltip card matching NMapGUI popup style
        hn_line = f"<span style='color:#64748b'>Host: {hostname}</span><br>" if hostname != ip else ""
        hover = (
            f"<b style='color:{color}'>Hop {hop['ttl']}</b><br>"
            f"<span style='color:#94a3b8'>IP: {ip}</span><br>"
            f"{hn_line}"
            f"<span style='color:#94a3b8'>RTT: {rtt_str}</span><br>"
            f"<span style='color:#64748b'>ICMP: {icmp_str}</span>"
        )
        if is_target:
            hover += "<br><span style='color:#22c55e'>&#10003; Target reached</span>"

        n_x.append(hop["_x"]); n_y.append(hop["_y"])
        n_colors.append(color); n_sizes.append(sz); n_borders.append(border)
        n_texts.append(label); n_hovers.append(hover)

    traces.append(go.Scatter(
        x=n_x, y=n_y,
        mode='markers+text',
        marker=dict(
            color=n_colors, size=n_sizes,
            line=dict(color=n_borders, width=1.5),
            symbol='circle',
        ),
        text=n_texts,
        textposition='top center',
        textfont=dict(family='JetBrains Mono, monospace', size=8, color='#94a3b8'),
        hovertemplate="%{customdata}<extra></extra>",
        customdata=n_hovers,
        showlegend=False
    ))

    # --- Figure ---
    all_x = [h["_x"] for h in valid_hops]
    all_y = [h["_y"] for h in valid_hops]
    pad_x = max((max(all_x) - min(all_x)) * 0.08, 0.5)
    pad_y = max((max(all_y) - min(all_y)) * 0.25, 1.8)

    fig = go.Figure(data=traces)
    fig.update_layout(
        paper_bgcolor='rgba(10,22,40,0.0)',
        plot_bgcolor='rgba(10,22,40,0.0)',
        height=360,
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis=dict(visible=False, range=[min(all_x) - pad_x, max(all_x) + pad_x]),
        yaxis=dict(visible=False, range=[min(all_y) - pad_y, max(all_y) + pad_y]),
        hovermode='closest',
        dragmode=False,
        font=dict(family='JetBrains Mono, monospace', color='#94a3b8')
    )
    return fig


# --- 5. MAIN CATEGORY NAVIGATION ---
menu_selection = option_menu(
    menu_title=None,
    options=["Home", "Web Based Security Tools", "Local Security Tools"],
    icons=["house", "globe", "shield-lock"],
    default_index=0,
    orientation="horizontal",
    styles={
        "container": {
            "padding": "0!important",
            "background-color": "transparent",
            "margin-bottom": "15px",
            "border": "none"
        },
        "icon": {
            "font-size": "16px"
        },
        "nav-link": {
            "font-size": "14px",
            "text-align": "center",
            "margin": "0px",
            "--hover-color": "transparent",
            "color": "#64748b",
            "border-radius": "0px",
            "padding": "10px 5px",
            "border-bottom": "2px solid transparent",
            "transition": "all 0.3s ease"
        },
        "nav-link-selected": {
            "background-color": "transparent",
            "color": "#e2e8f0",
            "border-bottom": "2px solid #ff4b4b",
            "font-weight": "600"
        },
    }
)

# Stop processes on outer menu switch
if 'last_menu' not in st.session_state:
    st.session_state.last_menu = menu_selection
if st.session_state.last_menu != menu_selection:
    if st.session_state.get('capturing'):
        st.session_state.capturing = False
    if st.session_state.get('scan_running'):
        cancel_event = st.session_state.get('_cancel_event')
        if cancel_event:
            cancel_event.set()
        st.session_state.scan_running = False
    st.session_state.last_menu = menu_selection

# ==========================================
# CATEGORY UNO: HOME PAGE
# ==========================================
if menu_selection == "Home":
    st.markdown("### Welcome to PASSECURIST!")
    st.write("Navigate through our toolkit using the menu above. Below is a quick overview of what you can do:")

    col1, col2 = st.columns(2)
    with col1:
        st.info("**🌐 Web Based Security Tools**\n\n"
                "- **Password Strength Analyzer:** Evaluate your passwords' structural complexity.\n"
                "- **Secure Password Generator:** Create cryptographically secure passwords and SHA-256 hashes.\n"
                "- **Web Form Validator:** Simulate and sanitize inputs against XSS and SQL injection attacks.")
    with col2:
        st.success("**💻 Local Security Tools**\n\n"
                   "- **Network Port Scanner:** Scan local or remote hosts for open ports.\n"
                   "- **Traffic Analyzer:** Sniff network packets in real-time with custom BPF filtering.")

# ==========================================
# CATEGORY DOS: WEB BASED SECURITY TOOLS
# ==========================================
elif menu_selection == "Web Based Security Tools":
    web_t1, web_t2, web_t3 = st.tabs(["Password Strength Analyzer", "Secure Password Generator", "Web Form Validator"])

    with web_t1:
        c_left, c_center, c_right = st.columns([1, 2, 1])
        with c_center:
            st.markdown("### Password Strength")
            st.caption("Type a password to analyze its complexity and entropy in real-time.")
            show_pwd = st.toggle("Hide & Unhide Password", value=False)
            pwd_type = "default" if show_pwd else "password"
            current_val = st.session_state.get("strength_input", "")
            password = st_keyup("Password", value=current_val, type=pwd_type, key="strength_input", label_visibility="collapsed", placeholder="Type your password here...")

            if password:
                rating, color, feedback = evaluate_password_strength(password)
                st.markdown("---")
                percent = 25 if rating == "WEAK" else (60 if rating == "MODERATE" else 100)

                col_res, col_prog = st.columns([1, 3])
                with col_res:
                    if rating == "WEAK": st.error(f"**{rating}**")
                    elif rating == "MODERATE": st.warning(f"**{rating}**")
                    else: st.success(f"**{rating}**")

                with col_prog:
                    st.progress(percent, text=f"**Strength Score: {percent}%**")

                with st.expander("Security Analysis Details", expanded=True):
                    for msg in feedback:
                        if "Correct" in msg or "Excellent" in msg: st.markdown(f":green[✅ {msg}]")
                        else: st.markdown(f":orange[⚠️ {msg}]")
            else:
                st.info("Start typing a password to see real-time analysis.")

    with web_t2:
        spacer_l, main_col, spacer_r = st.columns([1, 2, 1])
        with main_col:
            st.markdown("### Secure Password Generator")
            c1, c2 = st.columns([3, 1])
            with c1: length = st.slider("Length", 8, 32, 12)
            with c2:
                st.markdown("<br>", unsafe_allow_html=True)
                generate_btn = st.button("Generate", key="btn_gen")

            st.markdown("---")
            if generate_btn:
                pwd = generate_password(length)
                salt, pwd_hash = hash_password(pwd)
                st.session_state['gen_pwd'] = pwd
                st.session_state['gen_hash'] = pwd_hash
                st.session_state['gen_salt'] = salt

            if 'gen_pwd' in st.session_state:
                st.markdown("**Generated Password**")
                st.code(st.session_state['gen_pwd'], language=None)
                st.markdown("**SHA-256 Hash**")
                st.code(st.session_state['gen_hash'], language=None)
                st.markdown("**Salt**")
                st.code(st.session_state['gen_salt'], language=None)

                from datetime import datetime
                if st.button("💾 Save Hash to Audit Log"):
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if save_to_file(st.session_state['gen_salt'], st.session_state['gen_hash'], ts):
                        st.toast("Successfully saved to data/passwords.txt", icon="✅")

    with web_t3:
        st.markdown("### Web Form Validator")
        st.caption("Test inputs for XSS and SQL Injection vulnerabilities.")
        with st.form("web_form"):
            c1, c2, c3 = st.columns(3)
            with c1: name = st.text_input("Full Name", placeholder="Jane D.")
            with c2: email = st.text_input("Email Address", placeholder="yum@sushi.com")
            with c3: username = st.text_input("Username", placeholder="JaneD03")

            message = st.text_area("Message Payload", height=100, placeholder="Type your message here...")
            submitted = st.form_submit_button("Validate & Sanitize")

            if submitted:
                data = {"full_name": name, "email": email, "username": username, "message": message}
                results = validate_and_sanitize_form(data)
                st.markdown("---")

                if results['all_valid']: st.success("✅ **PASSED:** All inputs are valid and safe.")
                else: st.error("❌ **FAILED:** Security violations detected.")

                if results['errors']:
                    st.markdown("#### 🚫 Violation Report")
                    for err in results['errors']: st.error(err, icon="🚫")

                if results['summary']:
                    st.markdown("#### 🛠️ Sanitization Actions")
                    with st.container(border=True):
                        for log in results['summary']: st.markdown(f"🔧 `{log}`")

                    st.markdown("#### 🧼 Final Sanitized Output")
                    with st.container(border=True):
                        c_clean1, c_clean2 = st.columns(2)
                        with c_clean1:
                            st.markdown("**Sanitized Email:**"); st.code(results['sanitized']['email'], language=None)
                            st.markdown("**Sanitized Username:**"); st.code(results['sanitized']['username'], language=None)
                        with c_clean2:
                            st.markdown("**Sanitized Message:**"); st.code(results['sanitized']['message'], language=None)
                elif results['all_valid']:
                    st.info("No sanitization needed. Input is clean.")


# ==========================================
# CATEGORY TRES: LOCAL SECURITY TOOLS
# ==========================================
elif menu_selection == "Local Security Tools":
    loc_t1, loc_t2 = st.tabs(["Network Port Scanner", "Traffic Analyzer"])

    # --- Initialize session state ---
    if 'capturing' not in st.session_state:
        st.session_state.capturing = False
    if 'scan_running' not in st.session_state:
        st.session_state.scan_running = False
    if 'captured_data' not in st.session_state:
        st.session_state.captured_data = []
    if 'raw_packets' not in st.session_state:
        st.session_state.raw_packets = []
    if 'scan_results_live' not in st.session_state:
        st.session_state.scan_results_live = []
    if 'scan_progress' not in st.session_state:
        st.session_state.scan_progress = 0
    if 'scan_status' not in st.session_state:
        st.session_state.scan_status = ""
    if '_last_capture_ping' not in st.session_state:
        st.session_state['_last_capture_ping'] = 0.0
    if 'scan_start_time' not in st.session_state:
        st.session_state.scan_start_time = None
    if 'scan_end_time' not in st.session_state:
        st.session_state.scan_end_time = None
    if 'traceroute_hops' not in st.session_state:
        st.session_state.traceroute_hops = None
    if 'traceroute_host' not in st.session_state:
        st.session_state.traceroute_host = None

    if st.session_state.get('capturing'):
        _ping = st.session_state['_last_capture_ping']
        if _ping != 0.0 and (time.time() - _ping) > 30.0:
            st.session_state.capturing = False

    nps_is_running = st.session_state.get('scan_running', False)
    nta_is_running = st.session_state.get('capturing', False)

    # -----------------------------------
    # TOOL 1: NETWORK PORT SCANNER
    # -----------------------------------
    with loc_t1:
        nps_locked = nta_is_running

        st.markdown("### Network Port Scanner")
        st.caption("Discover open ports and services on a target machine.")

        if nps_locked:
            st.warning(
                "⚠️ **Network Traffic Analyzer is active.** "
                "Switch to the Traffic Analyzer tab and click ⏸ Pause first.",
                icon="🔒"
            )

        c1, c2 = st.columns([1, 2])

        with c1:
            st.markdown("#### Configuration")
            target_host = st.text_input("Target Host (IP or Domain)", value="127.0.0.1", disabled=nps_locked)
            preset = st.selectbox("Port Presets", list(PORT_PRESETS.keys()), disabled=nps_locked)
            start_port_input = st.text_input("Start Port", value=PORT_PRESETS[preset]['start'], disabled=nps_locked)
            end_port_input = st.text_input("End Port", value=PORT_PRESETS[preset]['end'], disabled=nps_locked)
            st.caption(f"ℹ️ *{PORT_PRESETS[preset]['description']}*")

            col_scan, col_stop_scan, col_clear = st.columns(3)
            with col_scan:
                start_scan = st.button("▶ Start Scan", use_container_width=True,
                                       disabled=(nps_locked or nps_is_running))
            with col_stop_scan:
                if st.button("⏹ Stop Scan", use_container_width=True, disabled=not nps_is_running):
                    _ce = st.session_state.get('_cancel_event')
                    if _ce:
                        _ce.set()
                    st.session_state.scan_running = False
                    st.session_state.scan_status = ""
                    st.session_state.scan_end_time = time.time()
                    st.rerun()
            with col_clear:
                if st.button("🗑 Clear Results", key="clear_ports", use_container_width=True,
                             disabled=(nps_locked or nps_is_running)):
                    for k in ('open_ports_found', 'scan_host', 'total_ports_scanned',
                              'traceroute_hops', 'traceroute_host'):
                        st.session_state.pop(k, None)
                    st.session_state.scan_running = False
                    st.session_state.scan_results_live = []
                    st.session_state.scan_progress = 0
                    st.session_state.scan_status = ""
                    st.session_state.scan_start_time = None
                    st.session_state.scan_end_time = None
                    if '_cancel_event' in st.session_state:
                        st.session_state['_cancel_event'].set()
                    st.rerun()

        with c2:
            st.markdown("#### Real-time Results")
            results_placeholder = st.empty()

            if start_scan and not nps_locked:
                is_valid_host, host_err = validate_host(target_host)
                is_valid_range, p_start, p_end, range_err = validate_port_range(start_port_input, end_port_input)

                if not is_valid_host:
                    st.error(f"Host Error: {host_err}")
                elif not is_valid_range:
                    st.error(f"Range Error: {range_err}")
                else:
                    cancel_event = threading.Event()
                    thread_results = []
                    thread_state = {"progress": 0.0, "status": "scanning"}

                    st.session_state['_cancel_event'] = cancel_event
                    st.session_state['_thread_results'] = thread_results
                    st.session_state['_thread_state'] = thread_state
                    st.session_state.scan_running = True
                    st.session_state.scan_results_live = []
                    st.session_state.scan_progress = 0
                    st.session_state.scan_status = "scanning"
                    st.session_state.scan_start_time = time.time()
                    st.session_state.scan_end_time = None
                    st.session_state.traceroute_hops = None
                    for k in ('open_ports_found', 'scan_host', 'total_ports_scanned'):
                        st.session_state.pop(k, None)

                    PORT_DESCRIPTIONS = {
                        20: "FTP Data Transfer", 21: "FTP Command Control", 22: "Secure Shell (SSH)",
                        23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
                        69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP", 143: "IMAP",
                        161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
                        3389: "RDP - Remote Desktop", 5060: "SIP"
                    }
                    total_ports = (p_end - p_start) + 1

                    def run_scan():
                        count = [0]

                        def callback(port, is_open):
                            if cancel_event.is_set():
                                return
                            count[0] += 1
                            thread_state["progress"] = min(count[0] / total_ports, 1.0)
                            if is_open:
                                desc = PORT_DESCRIPTIONS.get(port, "Dynamic/Private Port")
                                thread_results.append({
                                    "Port": port,
                                    "Service": get_service_name(port),
                                    "Description": desc,
                                    "Status": "OPEN"
                                })

                        scan_port_range(
                            target_host, p_start, p_end,
                            callback=callback,
                            cancel_check=lambda: cancel_event.is_set()
                        )
                        thread_state["status"] = "cancelled" if cancel_event.is_set() else "done"
                        thread_state["total_scanned"] = count[0]

                    threading.Thread(target=run_scan, daemon=True, name="run_scan").start()
                    st.rerun()

            if nps_is_running:
                thread_state = st.session_state.get('_thread_state', {})
                thread_results = st.session_state.get('_thread_results', [])

                st.session_state.scan_progress = thread_state.get("progress", 0)
                st.session_state.scan_results_live = list(thread_results)

                status = thread_state.get("status", "scanning")

                if status == "scanning":
                    st.warning(
                        "🚨 **DO NOT SWITCH TO ANOTHER TOOLS PAGE (e.g., Web Based Security Tools)!** "
                        "Switching to another page will auto-stop your scan.",
                        icon="⚠️"
                    )
                    st.progress(
                        st.session_state.scan_progress,
                        text=f"Scanning ports... {int(st.session_state.scan_progress * 100)}%"
                    )
                    if st.session_state.scan_results_live:
                        results_placeholder.dataframe(
                            pd.DataFrame(st.session_state.scan_results_live),
                            use_container_width=True
                        )
                else:
                    st.session_state.scan_running = False
                    st.session_state.scan_status = status
                    st.session_state.scan_end_time = time.time()
                    if status == "done":
                        st.session_state['scan_host'] = target_host
                        st.session_state['open_ports_found'] = list(thread_results)
                        st.session_state['total_ports_scanned'] = thread_state.get("total_scanned", 0)

            if st.session_state.get('scan_status') == 'done' and not st.session_state.get('open_ports_found'):
                st.info("Scan complete — no open ports found in the specified range.")
                st.session_state.scan_status = ""

            if st.session_state.get('open_ports_found') is not None:
                df_final = pd.DataFrame(st.session_state['open_ports_found'])
                if not df_final.empty:
                    results_placeholder.dataframe(df_final, use_container_width=True)
                csv_data = df_final.to_csv(index=False).encode('utf-8') if not df_final.empty else b""
                _, dl_col, _ = st.columns([1, 2, 1])
                with dl_col:
                    if not df_final.empty:
                        st.download_button(
                            "📥 Export Scan Report (CSV)",
                            data=csv_data,
                            file_name=f"PortScan_{st.session_state['scan_host']}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )

        # --- SCAN VISUALIZATIONS ---
        open_ports_data = st.session_state.get('open_ports_found')
        if open_ports_data is not None and not nps_is_running:
            df_viz = pd.DataFrame(open_ports_data)
            total_scanned = st.session_state.get('total_ports_scanned', 0)
            t_start = st.session_state.get('scan_start_time')
            t_end = st.session_state.get('scan_end_time')
            scan_duration = round(t_end - t_start, 1) if t_start and t_end else 0
            open_count = len(df_viz)
            closed_count = max(total_scanned - open_count, 0)

            st.markdown("---")
            with st.expander("Scan Analysis", expanded=True):

                # --- STAT/KPI CARDS ---
                s1, s2, s3, s4 = st.columns(4)
                with s1:
                    st.markdown(f"""<div class="stat-card"><div class="stat-label">Ports Scanned</div>
                        <div class="stat-number stat-total">{total_scanned:,}</div></div>""", unsafe_allow_html=True)
                with s2:
                    st.markdown(f"""<div class="stat-card"><div class="stat-label">Open Ports</div>
                        <div class="stat-number stat-open">{open_count}</div></div>""", unsafe_allow_html=True)
                with s3:
                    st.markdown(f"""<div class="stat-card"><div class="stat-label">Closed Ports</div>
                        <div class="stat-number stat-closed">{closed_count:,}</div></div>""", unsafe_allow_html=True)
                with s4:
                    st.markdown(f"""<div class="stat-card"><div class="stat-label">Scan Duration</div>
                        <div class="stat-number stat-neutral">{scan_duration}s</div></div>""", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                if not df_viz.empty:
                    ch1, ch2 = st.columns(2)

                    with ch1:
                        st.markdown("##### Open vs Closed Ports")
                        fig_donut = go.Figure(go.Pie(
                            labels=["Open", "Closed"], values=[open_count, closed_count], hole=0.62,
                            marker=dict(colors=['#22c55e', '#ef4444'], line=dict(color='#0f172a', width=3)),
                            textinfo='label+percent', textfont=dict(size=12, color='#e2e8f0'),
                            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>'
                        ))
                        fig_donut.add_annotation(
                            text=f"<b>{open_count}</b><br><span style='font-size:10px'>OPEN</span>",
                            x=0.5, y=0.5, showarrow=False,
                            font=dict(size=18, color='#22c55e', family='JetBrains Mono, monospace'), align='center'
                        )
                        fig_donut.update_layout(**PLOTLY_LAYOUT, height=300, showlegend=True)
                        st.plotly_chart(fig_donut, use_container_width=True)

                    with ch2:
                        st.markdown("##### Open Ports by Service Category")
                        df_viz['Category'] = df_viz['Port'].apply(get_port_category)
                        cat_counts = df_viz['Category'].value_counts().reset_index()
                        cat_counts.columns = ['Category', 'Count']
                        cat_counts = cat_counts.sort_values('Count', ascending=True)

                        fig_bar = go.Figure(go.Bar(
                            x=cat_counts['Count'], y=cat_counts['Category'], orientation='h',
                            marker=dict(color=ACCENT_COLORS[:len(cat_counts)], line=dict(color='rgba(0,0,0,0)', width=0)),
                            text=cat_counts['Count'], textposition='outside',
                            textfont=dict(color='#94a3b8', size=11),
                            hovertemplate='<b>%{y}</b><br>Open ports: %{x}<extra></extra>'
                        ))
                        fig_bar.update_layout(**PLOTLY_LAYOUT, height=300,
                            xaxis=dict(gridcolor='#1e293b', showgrid=True, zeroline=False, tickfont=dict(color='#64748b')),
                            yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(color='#94a3b8')), showlegend=False)
                        st.plotly_chart(fig_bar, use_container_width=True)

                    st.markdown("##### Discovered Open Ports — Number Line")
                    port_nums = sorted(df_viz['Port'].tolist())
                    port_services = [get_service_name(p) for p in port_nums]

                    # Build spike traces (one vertical line per open port)
                    spike_traces = []
                    for pn, svc in zip(port_nums, port_services):
                        spike_traces.append(go.Scatter(
                            x=[pn, pn], y=[0, 1],
                            mode='lines',
                            line=dict(color='#38bdf8', width=2),
                            hoverinfo='skip', showlegend=False
                        ))

                    fig_ports = go.Figure(spike_traces)
                    fig_ports.add_trace(go.Scatter(
                        x=port_nums, y=[1] * len(port_nums),
                        mode='markers+text',
                        marker=dict(color='#38bdf8', size=10, line=dict(color='#0ea5e9', width=2)),
                        text=port_services,
                        textposition='top center',
                        textfont=dict(size=9, color='#64748b'),
                        customdata=port_nums,
                        hovertemplate='<b>Port %{customdata}</b><br>Service: %{text}<extra></extra>',
                        showlegend=False
                    ))
                    fig_ports.add_shape(type='line', x0=0, x1=1, xref='paper',
                                        y0=0, y1=0, yref='y',
                                        line=dict(color='#334155', width=1))
                    fig_ports.update_layout(**PLOTLY_LAYOUT, height=200,
                        xaxis=dict(title='Port Number', tickfont=dict(color='#64748b', size=10),
                                   title_font=dict(color='#475569'), gridcolor='#1e293b',
                                   showgrid=True, zeroline=False),
                        yaxis=dict(visible=False, range=[-0.1, 1.6]),
                        showlegend=False)
                    st.plotly_chart(fig_ports, use_container_width=True)

                else:
                    st.info("No open ports found — nothing to visualize.")

            # --- TRACEROUTE SECTION ---
            st.markdown("---")
            with st.expander("Network Path — Traceroute", expanded=True):

                scapy_ok, privs_ok, _ = get_scapy_status()
                scan_host = st.session_state.get('scan_host', '127.0.0.1')

                if not scapy_ok or not privs_ok:
                    st.warning("⚠️ Traceroute requires admin/root privileges. Restart the app with elevated permissions to enable this feature.", icon="🔒")
                else:
                    # Controls row
                    tr_col1, tr_col2, tr_col3, tr_col4 = st.columns([3, 1, 1, 1])
                    with tr_col1:
                        tr_target = st.text_input(
                            "Target Host", value=scan_host,
                            placeholder="Target IP or hostname", key="tr_target_input"
                        )
                    with tr_col2:
                        tr_min_ttl = st.number_input(
                            "Min TTL", min_value=1, max_value=30, value=1, key="tr_min_ttl",
                            help="**Minimum TTL (Starting Hop)**\n\nTTL 1 = your default gateway (recommended). Set higher to skip the first N hops — useful on large enterprise or VPN networks where early hops are known and irrelevant. Valid range: 1–30 per IETF RFC 1393."
                        )
                    with tr_col3:
                        tr_max_ttl = st.number_input(
                            "Max TTL", min_value=1, max_value=64, value=30, key="tr_max_ttl",
                            help="**Maximum TTL (Hop Limit)**\n\nControls how many hops to probe before giving up. Internet standard (RFC 1393) recommends 30 as the default. Set to 64 for very distant or asymmetric routes. Most paths across the public internet resolve within 20–25 hops; setting above 30 is rarely needed but supported up to 64 here."
                        )
                    with tr_col4:
                        st.markdown("<br>", unsafe_allow_html=True)
                        run_tr = st.button("Trace Route", use_container_width=True, key="btn_traceroute")

                    if run_tr and tr_target:
                        with st.spinner(f"Tracing route to {tr_target}…"):
                            hops = run_scapy_traceroute(tr_target, min_ttl=tr_min_ttl, max_ttl=tr_max_ttl)
                        st.session_state.traceroute_hops = hops
                        st.session_state.traceroute_host = tr_target

                    hops = st.session_state.get('traceroute_hops')

                    if hops:
                        if "error" in hops[0]:
                            st.error(f"Traceroute failed: {hops[0]['error']}")
                        else:
                            valid_hops = [h for h in hops if h.get("responded")]
                            no_resp    = [h for h in hops if not h.get("responded")]
                            reached    = any(h.get("is_target") for h in hops)
                            last_rtt   = next((h["rtt_ms"] for h in reversed(valid_hops) if h.get("rtt_ms")), None)

                            # KPI cards (uniform font-size)
                            tk1, tk2, tk3, tk4 = st.columns(4)
                            with tk1:
                                st.markdown(f"""<div class="stat-card"><div class="stat-label">Total Hops</div>
                                    <div class="stat-number stat-total">{len(valid_hops)}</div></div>""", unsafe_allow_html=True)
                            with tk2:
                                rc = "stat-open" if reached else "stat-closed"
                                rv = "Yes" if reached else "No"
                                st.markdown(f"""<div class="stat-card"><div class="stat-label">Target Reached</div>
                                    <div class="stat-number {rc}">{rv}</div></div>""", unsafe_allow_html=True)
                            with tk3:
                                st.markdown(f"""<div class="stat-card"><div class="stat-label">No-Response Hops</div>
                                    <div class="stat-number stat-neutral">{len(no_resp)}</div></div>""", unsafe_allow_html=True)
                            with tk4:
                                rtt_disp = f"{last_rtt}ms" if last_rtt else "—"
                                st.markdown(f"""<div class="stat-card"><div class="stat-label">Final RTT</div>
                                    <div class="stat-number stat-neutral">{rtt_disp}</div></div>""", unsafe_allow_html=True)

                            st.markdown("<br>", unsafe_allow_html=True)

                            # Graph panel header + legend
                            st.markdown("""
                                <div class="tr-controls">
                                    <span class="tr-badge">Network Path</span>
                                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#334155;margin-left:auto">
                                        Hover nodes for details
                                    </span>
                                </div>
                                <div class="tr-graph-wrap">
                                    <div class="tr-legend">
                                        <div class="tr-legend-item">
                                            <span class="tr-dot" style="background:#38bdf8;box-shadow:0 0 5px #38bdf8"></span>
                                            You (origin)
                                        </div>
                                        <div class="tr-legend-item">
                                            <span class="tr-dot" style="background:#3b82f6;box-shadow:0 0 4px #2563eb"></span>
                                            Intermediate hop
                                        </div>
                                        <div class="tr-legend-item">
                                            <span class="tr-dot" style="background:#22c55e;box-shadow:0 0 5px #22c55e"></span>
                                            Target host
                                        </div>
                                        <div class="tr-legend-item">
                                            <span class="tr-dot" style="background:#334155"></span>
                                            No response (* * *)
                                        </div>
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)

                            fig_tr = build_traceroute_graph(hops, st.session_state.get('traceroute_host', ''))
                            if fig_tr:
                                st.plotly_chart(fig_tr, use_container_width=True, key="traceroute_graph")

                            # Hop detail table
                            with st.expander("Hop Details", expanded=False):
                                hop_rows = []
                                for h in hops:
                                    hostname = h.get("hostname", h["ip"])
                                    icmp_t   = h.get("icmp_type")
                                    icmp_str = {0: "Echo Reply (0)", 11: "Time Exceeded (11)"}.get(icmp_t, str(icmp_t)) if icmp_t is not None else "—"
                                    status   = "Target" if h.get("is_target") else ("Hop" if h.get("responded") else "No Response")
                                    hop_rows.append({
                                        "TTL":        h["ttl"],
                                        "IP Address": h["ip"],
                                        "Hostname":   hostname if hostname != h["ip"] else "—",
                                        "RTT (ms)":   h["rtt_ms"] if h.get("rtt_ms") else "—",
                                        "ICMP Type":  icmp_str,
                                        "Status":     status,
                                    })
                                st.dataframe(pd.DataFrame(hop_rows), use_container_width=True)

    # -----------------------------------
    # TOOL 2: TRAFFIC ANALYZER
    # -----------------------------------
    with loc_t2:
        nta_locked = nps_is_running

        st.markdown("### Network Traffic Analyzer")
        st.caption("Capture and analyze network packets in real-time. (Requires Scapy & Admin privileges!)")

        if nta_locked:
            st.warning(
                "⚠️ **Network Port Scanner is active.** "
                "Switch to the Network Port Scanner tab and click ⏹ Stop Scan first.",
                icon="🔒"
            )

        scapy_ok, privs_ok, status_msg = get_scapy_status()

        if not scapy_ok or not privs_ok:
            st.error(f"⚠️ **System Check Failed:** {status_msg}")
        else:
            c1, c2 = st.columns([1, 2])

            with c1:
                st.markdown("#### Filter Settings")
                proto_filter  = st.text_input("Protocol Filter", placeholder="e.g., tcp, udp, icmp", disabled=nta_locked)
                port_filter   = st.text_input("Port Filter", placeholder="e.g., 80, 443", disabled=nta_locked)
                ipHost_filter = st.text_input("General IP/Host Filter", placeholder="e.g., 192.168.1.1", disabled=nta_locked)

                col_src, col_dst = st.columns(2)
                with col_src:
                    src_filter = st.text_input("Source IP", placeholder="e.g., 10.0.0.5", disabled=nta_locked)
                with col_dst:
                    dst_filter = st.text_input("Destination IP", placeholder="e.g., 8.8.8.8", disabled=nta_locked)

                pkt_count = st.number_input("Packet Limit", min_value=0, max_value=10000, value=0,
                                            help="Set to 0 for NO LIMIT scanning.", disabled=nta_locked)

                col_cap, col_pause, col_clr = st.columns(3)
                with col_cap:
                    btn_label = "▶ Resume" if st.session_state.captured_data else "▶ Start"
                    if st.button(btn_label, disabled=(nta_is_running or nta_locked), use_container_width=True):
                        st.session_state.capturing = True
                        st.session_state['_last_capture_ping'] = time.time()
                        st.rerun()
                with col_pause:
                    if st.button("⏸ Pause", disabled=(not nta_is_running or nta_locked), use_container_width=True):
                        st.session_state.capturing = False
                        st.rerun()
                with col_clr:
                    if st.button("🗑 Clear Output", disabled=(nta_is_running or nta_locked), use_container_width=True):
                        st.session_state.captured_data = []
                        st.session_state.raw_packets = []
                        st.rerun()

            with c2:
                st.markdown("#### Captured Traffic")
                traffic_placeholder = st.empty()

                if st.session_state.captured_data:
                    df_show = pd.DataFrame(st.session_state.captured_data)
                    df_show['Dst Port'] = df_show['Dst Port'].astype(str)
                    df_show = df_show.iloc[::-1].reset_index(drop=True)
                    traffic_placeholder.dataframe(df_show, use_container_width=True)

                if st.session_state.capturing and not nta_locked:
                    st.warning(
                        "🚨 **DO NOT SWITCH TO ANOTHER TOOLS PAGE (e.g., Web Based Security Tools)!** "
                        "Switching to another page will auto-stop your capture.",
                        icon="⚠️"
                    )

                    is_valid_filt, result = validate_filter(
                        proto=proto_filter,
                        port=port_filter,
                        host=ipHost_filter,
                        src_ip=src_filter,
                        dst_ip=dst_filter
                    )
                    final_filter = result if is_valid_filt else ""
                    st.info("🔄 Capturing packets... Click '⏸ Pause' to pause.")

                    MAC_VENDORS = {
                        "00:50:56": "VMware", "00:15:5D": "Microsoft", "00:1A:11": "Google",
                        "8C:8C:AA": "Apple", "28:16:A8": "Intel", "00:24:E8": "Cisco"
                    }

                    def update_traffic_ui(pkt_info):
                        src_mac = pkt_info.get('src_mac', 'N/A')
                        vendor = MAC_VENDORS.get(str(src_mac).upper()[:8], "Generic Device") if src_mac != 'N/A' else "Unknown"
                        st.session_state.captured_data.append({
                            "Time": pkt_info['timestamp'], "Proto": pkt_info['protocol'],
                            "Src Vendor": vendor, "Src MAC": src_mac, "Src IP": pkt_info['src_ip'],
                            "Dst IP": pkt_info['dst_ip'], "Dst Port": pkt_info['dst_port'], "Summary": pkt_info['summary']
                        })

                    try:
                        st.session_state['_last_capture_ping'] = time.time()

                        if pkt_count > 0:
                            remaining = pkt_count - len(st.session_state.captured_data)
                            batch_size = min(5, remaining)
                        else:
                            batch_size = 5

                        batch_raw = start_packet_capture(
                            filter_string=final_filter,
                            packet_callback=update_traffic_ui,
                            count=batch_size
                        )
                        st.session_state['_last_capture_ping'] = time.time()
                        st.session_state.raw_packets.extend(batch_raw)

                        if st.session_state.captured_data:
                            df_live = pd.DataFrame(st.session_state.captured_data)
                            df_live['Dst Port'] = df_live['Dst Port'].astype(str)
                            df_live = df_live.iloc[::-1].reset_index(drop=True)
                            traffic_placeholder.dataframe(df_live, use_container_width=True)

                        if pkt_count > 0 and len(st.session_state.captured_data) >= pkt_count:
                            st.session_state.capturing = False
                            st.success(f"✅ Reached limit of {pkt_count} packets!")

                    except Exception as e:
                        st.error(f"Capture failed: {e}")
                        st.session_state.capturing = False

                if not st.session_state.capturing and st.session_state.captured_data and not nta_locked:
                    dl_col1, dl_col2 = st.columns(2)
                    with dl_col1:
                        csv_data = pd.DataFrame(st.session_state.captured_data).to_csv(index=False).encode('utf-8')
                        st.download_button("📥 Export CSV", data=csv_data, file_name="Traffic.csv", mime="text/csv", use_container_width=True)
                    with dl_col2:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp: tmp_path = tmp.name
                        wrpcap(tmp_path, st.session_state.raw_packets)
                        with open(tmp_path, "rb") as f: pcap_bytes = f.read()
                        os.remove(tmp_path)
                        st.download_button("📥 Export PCAP", data=pcap_bytes, file_name="Traffic.pcap", mime="application/vnd.tcpdump.pcap", use_container_width=True)

            # --- TRAFFIC VISUALIZATIONS ---
            if not st.session_state.capturing and st.session_state.captured_data and not nta_locked:
                df_traffic = pd.DataFrame(st.session_state.captured_data)

                st.markdown("---")
                with st.expander("Traffic Analysis", expanded=True):

                    total_pkts = len(df_traffic)
                    unique_src = df_traffic[df_traffic['Src IP'] != 'N/A']['Src IP'].nunique()
                    unique_dst = df_traffic[df_traffic['Dst IP'] != 'N/A']['Dst IP'].nunique()
                    proto_counts = df_traffic['Proto'].value_counts()
                    top_proto = proto_counts.index[0] if len(proto_counts) > 0 else "N/A"

                    s1, s2, s3, s4 = st.columns(4)
                    with s1:
                        st.markdown(f"""<div class="stat-card"><div class="stat-label">Total Packets</div>
                            <div class="stat-number stat-total">{total_pkts:,}</div></div>""", unsafe_allow_html=True)
                    with s2:
                        st.markdown(f"""<div class="stat-card"><div class="stat-label">Unique Sources</div>
                            <div class="stat-number stat-open">{unique_src}</div></div>""", unsafe_allow_html=True)
                    with s3:
                        st.markdown(f"""<div class="stat-card"><div class="stat-label">Unique Destinations</div>
                            <div class="stat-number stat-neutral">{unique_dst}</div></div>""", unsafe_allow_html=True)
                    with s4:
                        st.markdown(f"""<div class="stat-card"><div class="stat-label">Top Protocol</div>
                            <div class="stat-number stat-neutral" style="font-size:1.4rem">{top_proto}</div></div>""", unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    row1_c1, row1_c2 = st.columns(2)

                    with row1_c1:
                        st.markdown("##### Protocol Distribution")
                        proto_df = df_traffic['Proto'].value_counts().reset_index()
                        proto_df.columns = ['Protocol', 'Count']
                        proto_color_map = {'TCP': '#38bdf8', 'UDP': '#22c55e', 'ICMP': '#f59e0b', 'Other': '#94a3b8', 'Unknown': '#475569'}
                        colors = [proto_color_map.get(p, '#a78bfa') for p in proto_df['Protocol']]

                        fig_proto = go.Figure(go.Pie(
                            labels=proto_df['Protocol'], values=proto_df['Count'], hole=0.62,
                            marker=dict(colors=colors, line=dict(color='#0f172a', width=3)),
                            textinfo='label+percent', textfont=dict(size=12, color='#e2e8f0'),
                            hovertemplate='<b>%{label}</b><br>Packets: %{value}<br>%{percent}<extra></extra>'
                        ))
                        fig_proto.add_annotation(
                            text=f"<b>{total_pkts}</b><br><span style='font-size:10px'>PACKETS</span>",
                            x=0.5, y=0.5, showarrow=False,
                            font=dict(size=16, color='#38bdf8', family='JetBrains Mono, monospace'), align='center'
                        )
                        fig_proto.update_layout(**PLOTLY_LAYOUT, height=300)
                        st.plotly_chart(fig_proto, use_container_width=True)

                    with row1_c2:
                        st.markdown("##### Top 8 Source IPs (Talkers)")
                        src_counts = df_traffic['Src IP'].value_counts().head(8).reset_index()
                        src_counts.columns = ['IP', 'Packets']
                        src_counts = src_counts.sort_values('Packets', ascending=True)

                        fig_src = go.Figure(go.Bar(
                            x=src_counts['Packets'], y=src_counts['IP'], orientation='h',
                            marker=dict(color='#38bdf8', opacity=0.85, line=dict(color='rgba(0,0,0,0)')),
                            text=src_counts['Packets'], textposition='outside',
                            textfont=dict(color='#94a3b8', size=11),
                            hovertemplate='<b>%{y}</b><br>Packets: %{x}<extra></extra>'
                        ))
                        fig_src.update_layout(**PLOTLY_LAYOUT, height=300,
                            xaxis=dict(gridcolor='#1e293b', showgrid=True, zeroline=False, tickfont=dict(color='#64748b')),
                            yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(color='#94a3b8', size=10)), showlegend=False)
                        st.plotly_chart(fig_src, use_container_width=True)

                    row2_c1, row2_c2 = st.columns(2)

                    with row2_c1:
                        st.markdown("##### Top 10 Destination Ports")
                        dst_port_df = df_traffic['Dst Port'].astype(str)
                        dst_port_df = dst_port_df[dst_port_df != 'N/A']
                        top_ports = dst_port_df.value_counts().head(10).reset_index()
                        top_ports.columns = ['Port', 'Count']

                        # Treemap (each block sized by packet count, labeled with port + count)
                        fig_dport = go.Figure(go.Treemap(
                            labels=[f":{p}  {c} pkts" for p, c in zip(top_ports['Port'], top_ports['Count'])],
                            parents=[""] * len(top_ports),
                            values=top_ports['Count'],
                            textfont=dict(family='JetBrains Mono, monospace', size=12, color='#e2e8f0'),
                            marker=dict(
                                colors=top_ports['Count'],
                                colorscale=[[0, '#1e3a5f'], [0.5, '#1d4ed8'], [1, '#38bdf8']],
                                line=dict(color='#0f172a', width=2)
                            ),
                            hovertemplate='<b>Port %{label}</b><br>Packets: %{value}<extra></extra>',
                        ))
                        fig_dport.update_layout(**PLOTLY_LAYOUT, height=300)
                        st.plotly_chart(fig_dport, use_container_width=True)

                    with row2_c2:
                        st.markdown("##### Packet Volume Over Time")
                        try:
                            df_time = df_traffic.copy()
                            df_time['Second'] = pd.to_datetime(df_time['Time'].str[:19], format='%Y-%m-%d %H:%M:%S', errors='coerce')
                            df_time = df_time.dropna(subset=['Second'])
                            if len(df_time) > 0:
                                time_series = df_time.groupby('Second').size().reset_index(name='Packets')
                                fig_timeline = go.Figure()
                                fig_timeline.add_trace(go.Scatter(
                                    x=time_series['Second'], y=time_series['Packets'],
                                    mode='lines+markers',
                                    line=dict(color='#38bdf8', width=2),
                                    marker=dict(size=5, color='#0ea5e9', line=dict(color='#38bdf8', width=1)),
                                    fill='tozeroy', fillcolor='rgba(56, 189, 248, 0.08)',
                                    hovertemplate='<b>%{x}</b><br>Packets: %{y}<extra></extra>'
                                ))
                                fig_timeline.update_layout(**PLOTLY_LAYOUT, height=300,
                                    xaxis=dict(gridcolor='#1e293b', showgrid=True, zeroline=False, tickfont=dict(color='#64748b', size=9)),
                                    yaxis=dict(gridcolor='#1e293b', showgrid=True, zeroline=False, tickfont=dict(color='#64748b')),
                                    showlegend=False)
                                st.plotly_chart(fig_timeline, use_container_width=True)
                            else:
                                st.info("Not enough timestamped data for timeline.")
                        except Exception as e:
                            st.caption(f"Timeline unavailable: {e}")

                    vendor_counts = df_traffic['Src Vendor'].value_counts()
                    if len(vendor_counts) > 1 or (len(vendor_counts) == 1 and vendor_counts.index[0] not in ['Unknown', 'Generic Device']):
                        st.markdown("##### Source Device Vendor Breakdown")
                        vendor_df = vendor_counts.reset_index()
                        vendor_df.columns = ['Vendor', 'Count']
                        fig_vendor = go.Figure(go.Pie(
                            labels=vendor_df['Vendor'], values=vendor_df['Count'], hole=0.5,
                            marker=dict(colors=ACCENT_COLORS[:len(vendor_df)], line=dict(color='#0f172a', width=3)),
                            textinfo='label+percent', textfont=dict(size=11, color='#e2e8f0'),
                            hovertemplate='<b>%{label}</b><br>Packets: %{value}<br>%{percent}<extra></extra>'
                        ))
                        fig_vendor.update_layout(**PLOTLY_LAYOUT, height=280)
                        st.plotly_chart(fig_vendor, use_container_width=True)

# Auto-refresh while scans or captures are active since Streamlit doesn't support live-updating outputs without a rerun trigger
    if nps_is_running or nta_is_running:
        time.sleep(0.3)
        st.rerun()