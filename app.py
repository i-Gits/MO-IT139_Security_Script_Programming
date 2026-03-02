import streamlit as st
import sys
import os
import nltk
import pandas as pd 
import tempfile
import time
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

from features.network_port_scanner import PORT_PRESETS, validate_host, validate_port_range, scan_port_range, get_service_name
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
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# --- 4. HEADER ---
st.title("🛡️ PASSECURIST")
st.markdown("##### A Comprehensive Security Toolkit!")
st.markdown("###### Made by C. Encillo, H. Tantoco, J. Delas Armas, and M. Samaniego.")
st.markdown("---")

# --- 5. MAIN CATEGORY NAVIGATION  ---
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
                    st.rerun()
            with col_clear:
                if st.button("🗑 Clear Results", key="clear_ports", use_container_width=True,
                             disabled=(nps_locked or nps_is_running)):
                    st.session_state.pop('open_ports_found', None)
                    st.session_state.pop('scan_host', None)
                    st.session_state.scan_running = False
                    st.session_state.scan_results_live = []
                    st.session_state.scan_progress = 0
                    st.session_state.scan_status = ""
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
                    import threading

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
                    st.session_state.pop('open_ports_found', None)
                    st.session_state.pop('scan_host', None)

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
                    if status == "done":
                        st.session_state['scan_host'] = target_host
                        st.session_state['open_ports_found'] = list(thread_results)

            if st.session_state.get('scan_status') == 'done' and not st.session_state.get('open_ports_found'):
                st.info("Scan complete — no open ports found in the specified range.")
                st.session_state.scan_status = ""

            if st.session_state.get('open_ports_found'):
                df_final = pd.DataFrame(st.session_state['open_ports_found'])
                results_placeholder.dataframe(df_final, use_container_width=True)
                csv_data = df_final.to_csv(index=False).encode('utf-8')
                _, dl_col, _ = st.columns([1, 2, 1])
                with dl_col:
                    st.download_button(
                        "📥 Export Scan Report (CSV)",
                        data=csv_data,
                        file_name=f"PortScan_{st.session_state['scan_host']}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )

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
                proto_filter = st.text_input("Protocol Filter", placeholder="e.g., tcp, udp, icmp", disabled=nta_locked)
                port_filter = st.text_input("Port Filter", placeholder="e.g., 80, 443", disabled=nta_locked)
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

    if nps_is_running or nta_is_running:
        time.sleep(0.3)
        st.rerun()