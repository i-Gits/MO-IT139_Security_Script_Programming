import streamlit as st
import sys
import os
import nltk
import pandas as pd # needed for displaying the network data tables
from st_keyup import st_keyup

# --- 1. SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'src'))

# auto-download NLTK if missing cause this gave me a headache BRO
try:
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('words')

# import features
from features.password_strength import evaluate_password_strength
from features.password_generator import generate_password, hash_password, save_to_file
from features.webform_validator import validate_and_sanitize_form

# import local network features
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
    /* Dark Slate Background */
    .stApp {
        background-color: #0f172a;
        color: #e2e8f0;
    }
    
    /* Input Fields */
    .stTextInput > div > div > input, 
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div,
    .stNumberInput > div > div > input {
        background-color: #1e293b; 
        color: white;
        border: 1px solid #475569;
        border-radius: 6px;
        font-size: 14px;
    }
    
    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        margin-bottom: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 6px;
        color: #94a3b8;
        font-weight: 600;
        padding: 0 16px;
        border: 1px solid transparent;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #38bdf8 !important;
        border: 1px solid #334155 !important;
    }

    /* Buttons (Sky Blue) */
    .stButton > button {
        background-color: #38bdf8;
        color: #0f172a;
        font-weight: 900;
        border-radius: 6px;
        border: none;
        padding: 0.5rem 1rem;
        width: 100%;
        font-size: 14px;
    }
    .stButton > button:hover {
        background-color: #0ea5e9;
        color: white;
    }
    
    /* Progress Bar */
    .stProgress > div > div > div > div {
        background-color: #38bdf8;
    }
    
    /* Clean up top bar */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# --- 4. HEADER ---
st.title("🛡️ PASSECURIST")
st.markdown("##### A Comprehensive Security Toolkit!")
st.markdown("###### Made by C. Encillo, H. Tantoco, J. Delas Armas, and M. Samaniego.")
st.markdown("---")

# --- 5. MAIN CATEGORY NAVIGATION ---
tab_home, tab_web, tab_local = st.tabs(["Home", "Web Based Security Tools", "Local Security Tools"])

# ==========================================
# CATEGORY UNOO: HOME PAGE
# ==========================================
with tab_home:
    st.markdown("### Welcome to PASSECURIST!")
    st.write("Navigate through our toolkit using the tabs above. Below is a quick overview of what you can do:")
    
    col1, col2 = st.columns(2)
    with col1:
        st.info("**🌐 Web Based Security Tools**\n\n"
                "- **Password Strength Analyzer:** What it says on the tin; evaluate your passwords' structural complexity and check against dictionary words.\n"
                "- **Secure Password Generator:** Create cryptographically secure passwords and SHA-256 hashes.\n"
                "- **Web Form Validator:** Simulate and sanitize inputs against XSS and SQL injection attacks.")
    with col2:
        st.success("**💻 Local Security Tools**\n\n"
                   "- **Network Port Scanner:** Scan local or remote hosts for open ports and identify running services.\n"
                   "- **Traffic Analyzer:** Sniff network packets in real-time with custom BPF filtering (Admin access required!).")


# ==========================================
# CATEGORY DOS: WEB BASED SECURITY TOOLS
# ==========================================
with tab_web:
    # nest original tabs inside here!
    web_t1, web_t2, web_t3 = st.tabs(["Password Strength Analyzer", "Secure Password Generator", "Web Form Validator"])
    

    # --- TAB 1: PASSWORD STRONK ---

    with web_t1:
        # centered layout using columns
        c_left, c_center, c_right = st.columns([1, 2, 1])
        
        with c_center:
            st.markdown("### Password Strength")
            st.caption("Type a password to analyze its complexity and entropy in real-time.")
            
            # --- visibility toggle with memory ---
            show_pwd = st.toggle("Hide & Unhide Password", value=False)
            pwd_type = "default" if show_pwd else "password"
            
            # 1. grab the text from Streamlit's memory (if it exists)
            current_val = st.session_state.get("strength_input", "")
            
            # 2. psass it back into the box using value=current_val
            password = st_keyup("Password", value=current_val, type=pwd_type, key="strength_input", label_visibility="collapsed", placeholder="Type your password here...")
            
            if password:
                rating, color, feedback = evaluate_password_strength(password)
                
                st.markdown("---")
                
                # percentage and colour logic
                percent = 0
                if rating == "WEAK":
                    percent = 25
                    bar_color = "red"
                elif rating == "MODERATE":
                    percent = 60
                    bar_color = "orange"
                else:
                    percent = 100
                    bar_color = "green"

                # result header
                col_res, col_prog = st.columns([1, 3])
                with col_res:
                    if rating == "WEAK":
                        st.error(f"**{rating}**")
                    elif rating == "MODERATE":
                        st.warning(f"**{rating}**")
                    else:
                        st.success(f"**{rating}**")
                
                with col_prog:
                    # PROGRESS BAR WITH PERCENTAGE!
                    st.progress(percent, text=f"**Strength Score: {percent}%**")
                
                # feedback section
                with st.expander("Security Analysis Details", expanded=True):
                    for msg in feedback:
                        if "Correct" in msg or "Excellent" in msg:
                            st.markdown(f":green[✅ {msg}]")
                        else:
                            st.markdown(f":orange[⚠️ {msg}]")
            else:
                st.info("Start typing a password to see real-time analysis.")

    # --- TAB 2: PASSWORD GENERATOR ---
    with web_t2:
        spacer_l, main_col, spacer_r = st.columns([1, 2, 1])
        
        with main_col:
            st.markdown("### Secure Password Generator")
            
            # row 1: controls
            c1, c2 = st.columns([3, 1])
            with c1:
                length = st.slider("Length", 8, 32, 12)
            with c2:
                st.markdown("<br>", unsafe_allow_html=True) # spacer
                generate_btn = st.button("Generate", key="btn_gen")
            
            st.markdown("---")
            
            # logic
            if generate_btn:
                pwd = generate_password(length)
                salt, pwd_hash = hash_password(pwd)
                st.session_state['gen_pwd'] = pwd
                st.session_state['gen_hash'] = pwd_hash
                st.session_state['gen_salt'] = salt
                
            if 'gen_pwd' in st.session_state:
                # result card
                st.markdown("**Generated Password**")
                st.code(st.session_state['gen_pwd'], language=None)
                
                st.markdown("**SHA-256 Hash**")
                st.code(st.session_state['gen_hash'], language=None)
                
                st.markdown("**Salt**")
                st.code(st.session_state['gen_salt'], language=None)
                
                # save button
                from datetime import datetime
                if st.button("💾 Save Hash to Audit Log"):
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if save_to_file(st.session_state['gen_salt'], st.session_state['gen_hash'], ts):
                        st.toast("Successfully saved to data/passwords.txt", icon="✅")

    # --- TAB 3: WEB VALIDATOR ---
    with web_t3:
        st.markdown("### Web Form Validator")
        st.caption("Test inputs for XSS and SQL Injection vulnerabilities.")
        
        with st.form("web_form"):
            # grid
            c1, c2, c3 = st.columns(3)
            with c1:
                name = st.text_input("Full Name", placeholder="Jane D.")
            with c2:
                email = st.text_input("Email Address", placeholder="yum@sushi.com")
            with c3:
                username = st.text_input("Username", placeholder="JaneD03")
                
            message = st.text_area("Message Payload", height=100, placeholder="Type your message here...")
            
            submitted = st.form_submit_button("Validate & Sanitize")
            
            if submitted:
                data = {"full_name": name, "email": email, "username": username, "message": message}
                results = validate_and_sanitize_form(data)
                
                st.markdown("---")
                
                # 1. status banner
                if results['all_valid']:
                    st.success("✅ **PASSED:** All inputs are valid and safe.")
                else:
                    st.error("❌ **FAILED:** Security violations detected.")

                # 2. detailed breakdown
                if results['errors']:
                    st.markdown("#### 🚫 Violation Report")
                    for err in results['errors']:
                        st.error(err, icon="🚫")
                
                # 3. sanitazion summary
                if results['summary']:
                    st.markdown("#### 🛠️ Sanitization Actions")
                    with st.container(border=True):
                        for log in results['summary']:
                            st.markdown(f"🔧 `{log}`")
                    
                    # ---  SHOW THE CLEAN DATA ---
                    st.markdown("#### 🧼 Final Sanitized Output")
                    st.caption("This is the clean data that would be saved to the database:")
                    
                    # show the before/after or just the final clean result
                    with st.container(border=True):
                        c_clean1, c_clean2 = st.columns(2)
                        with c_clean1:
                            st.markdown("**Sanitized Email:**")
                            st.code(results['sanitized']['email'], language=None)
                            
                            st.markdown("**Sanitized Username:**")
                            st.code(results['sanitized']['username'], language=None)
                        
                        with c_clean2:
                            st.markdown("**Sanitized Message:**")
                            st.code(results['sanitized']['message'], language=None)

                elif results['all_valid']:
                    st.info("No sanitization needed. Input is clean.")


# ==========================================
# CATEGORY TRES: LOCAL SECURITY TOOLS
# ==========================================
with tab_local:
    # nested tabs for the new tools
    loc_t1, loc_t2 = st.tabs(["Network Port Scanner", "Traffic Analyzer"])
    
    # -----------------------------------
    # TOOL 1: NETWORK PORT SCANNER
    # -----------------------------------
    with loc_t1:
        st.markdown("### Network Port Scanner")
        st.caption("Discover open ports and services on a target machine.")
        
        c1, c2 = st.columns([1, 2])

        with c1:
            st.markdown("#### Configuration")
            target_host = st.text_input("Target Host (IP or Domain)", value="127.0.0.1")
            
            preset = st.selectbox("Port Presets", list(PORT_PRESETS.keys()))
            start_port_input = st.text_input("Start Port", value=PORT_PRESETS[preset]['start'])
            end_port_input = st.text_input("End Port", value=PORT_PRESETS[preset]['end'])
            
            st.caption(f"ℹ️ *{PORT_PRESETS[preset]['description']}*")
            
            col_scan, col_clear = st.columns(2)
            with col_scan:
                start_scan = st.button("Start Scan")
            with col_clear:
                if st.button("Clear Results", key="clear_ports"):
                    st.rerun()
                    
        with c2:
            st.markdown("#### Real-time Results")
            if start_scan:
                is_valid_host, host_err = validate_host(target_host)
                is_valid_range, p_start, p_end, range_err = validate_port_range(start_port_input, end_port_input)
                
                if not is_valid_host:
                    st.error(f"Host Error: {host_err}")
                elif not is_valid_range:
                    st.error(f"Range Error: {range_err}")
                else:
                    st.info(f"Scanning **{target_host}** from port {p_start} to {p_end}...")
                    
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    results_placeholder = st.empty()
                    
                    total_ports = (p_end - p_start) + 1
                    
                    # --- PORT DESCRIPTIONS DICTIONARY ---
                    PORT_DESCRIPTIONS = {
                        20: "FTP Data Transfer",
                        21: "FTP Command Control",
                        22: "Secure Shell (SSH) - Secure remote login",
                        23: "Telnet - Unencrypted text communications (Insecure)",
                        25: "SMTP - Email routing",
                        53: "DNS - Domain Name System",
                        67: "DHCP Server - IP assignment",
                        68: "DHCP Client",
                        69: "TFTP - Trivial File Transfer",
                        80: "HTTP - Unencrypted web traffic",
                        88: "Kerberos - Authentication protocol",
                        110: "POP3 - Email retrieval",
                        123: "NTP - Network Time Protocol",
                        143: "IMAP - Email retrieval",
                        161: "SNMP - Network management",
                        194: "IRC - Internet Relay Chat",
                        389: "LDAP - Directory access",
                        443: "HTTPS - Secure encrypted web traffic",
                        445: "SMB - Windows file sharing",
                        464: "Kerberos Change Password",
                        636: "LDAPS - Secure directory access",
                        1720: "H.323 - VoIP call signaling",
                        3389: "RDP - Windows Remote Desktop",
                        5060: "SIP - VoIP signaling",
                        5061: "SIP over TLS - Secure VoIP"
                    }

                    total_ports = (p_end - p_start) + 1
                    scan_state = {"count": 0} 
                    open_ports_found = []
                    
                    # callback for real-time ui updates
                    def update_scan_ui(port, is_open):
                        scan_state["count"] += 1
                        
                        progress_bar.progress(min(scan_state["count"] / total_ports, 1.0))
                        status_text.text(f"Scanning port {port}...")
                        
                        if is_open:
                            service = get_service_name(port)
                            # get the description, or default to generic if it's a random high port
                            desc = PORT_DESCRIPTIONS.get(port, "Dynamic/Private Port")
                            
                            # desc column
                            open_ports_found.append({
                                "Port": port, 
                                "Service": service, 
                                "Description": desc, 
                                "Status": "OPEN"
                            })
                            
                            df = pd.DataFrame(open_ports_found)
                            results_placeholder.dataframe(df, use_container_width=True)

                    try:
                        scan_port_range(target_host, p_start, p_end, callback=update_scan_ui)
                        status_text.success("Scan Complete!")
                        
                        if open_ports_found:
                            # --- EXPORT TO CSV FEATURE ---
                            df_final = pd.DataFrame(open_ports_found)
                            csv_data = df_final.to_csv(index=False).encode('utf-8')
                            
                            st.download_button(
                                label="Export Scan Report (CSV)",
                                data=csv_data,
                                file_name=f"PortScan_{target_host}.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
                        else:
                            results_placeholder.warning(f"No open ports found between {p_start} and {p_end}.")
                    except Exception as e:
                        st.error(f"An error occurred: {e}")

    # -----------------------------------
    # TOOL 2: TRAFFIC ANALYZER
    # -----------------------------------
    with loc_t2:
        st.markdown("### Network Traffic Analyzer")
        st.caption("Capture and analyze network packets in real-time. (Requires Scapy & Admin privileges!)")
        
        scapy_ok, privs_ok, status_msg = get_scapy_status()
        
        if not scapy_ok or not privs_ok:
            st.error(f"⚠️ **System Check Failed:** {status_msg}")
            st.info("You need to run your terminal as an Administrator (Windows) or use `sudo` (Mac/Linux) to capture packets.")
        else:
            st.success("✅ System Check Passed: Scapy installed and running with elevated privileges!")
            
            c1, c2 = st.columns([1, 2])
            with c1:
                st.markdown("#### Filter Settings")
                proto_filter = st.text_input("Protocol Filter", placeholder="e.g., tcp, udp, icmp", help="Leave blank to capture all protocols.")
                port_filter = st.text_input("Port Filter", placeholder="e.g., 80, 443", help="Leave blank to capture all ports.")
                ipHost_filter = st.text_input("IP/Host Filter", placeholder="e.g., 192.168.1.1 or example.com", help="Leave blank to capture all hosts.")
                pkt_count = st.number_input("Packet Limit", min_value=1, max_value=500, value=25, help="Stop capturing after this many packets.")
                
                col_cap, col_clr = st.columns(2)
                with col_cap:
                    start_capture = st.button("Start Capture")
                with col_clr:
                    if st.button("Clear Output", key="clear_traffic"):
                        st.rerun()

            with c2:
                st.markdown("#### Captured Traffic")
                if start_capture:
                    print("DEBUG INPUTS:")
                    print(f"  proto  = '{proto_filter.strip()}'")
                    print(f"  port   = '{port_filter.strip()}'")
                    print(f"  host   = '{ipHost_filter.strip()}'")
                    is_valid_filt, result = validate_filter(
                        proto=proto_filter.strip(),      
                        port=port_filter.strip(),         
                        host=ipHost_filter.strip()
                    )
                    print(f"DEBUG RESULT: valid={is_valid_filt}, filter='{result}'")
                    if not is_valid_filt:
                        st.error(f"Filter Error: {result}")
                    else:
                       
                        
                        final_filter = result
                        filter_display = f"`{final_filter}`" if final_filter else "all traffic (no filter)"
                        st.info(f"Using filter: {filter_display}")

                        st.info(f"Capturing up to {pkt_count} packets. Please wait...")

                        traffic_placeholder = st.empty()
                        captured_data = []
                        
                        # --- Mini MAC Vendor Database ---
                        # these are the first 8 characters (OUI) of common MAC addresses
                        MAC_VENDORS = {
                            "00:50:56": "VMware", "08:00:27": "VirtualBox", 
                            "00:15:5D": "Microsoft", "B8:27:EB": "Raspberry Pi",
                            "00:1A:11": "Google", "3C:5A:B4": "Google",
                            "00:14:22": "Dell", "00:24:E8": "Cisco",
                            "28:16:A8": "Intel", "8C:8C:AA": "Apple",
                            "F4:0F:24": "Apple", "00:E0:4C": "Realtek",
                            "CC:46:D6": "Cisco", "44:03:2C": "Intel"
                        }

                        def get_vendor(mac_str):
                            if mac_str == 'N/A' or not mac_str: return "Unknown"
                            prefix = str(mac_str).upper()[:8]
                            return MAC_VENDORS.get(prefix, "Generic Device")

                        # callback for real-time ui updates
                        def update_traffic_ui(pkt_info):
                            # Ggrab the MAC and look up the vendor
                            src_mac = pkt_info.get('src_mac', 'N/A')
                            vendor = get_vendor(src_mac)

                            captured_data.append({
                                "Time": pkt_info['timestamp'],
                                "Proto": pkt_info['protocol'],
                                "Src Vendor": vendor,        
                                "Src MAC": src_mac,            
                                "Src IP": pkt_info['src_ip'],
                                "Dst IP": pkt_info['dst_ip'],
                                "Dst Port": pkt_info['dst_port'],
                                "Summary": pkt_info['summary']
                            })
                          

                            if len(captured_data) % 5 == 0 or len(captured_data) >= pkt_count:
                                df = pd.DataFrame(captured_data)
                                traffic_placeholder.dataframe(df, use_container_width=True)

                        try:
                            start_packet_capture(
                                filter_string=final_filter, 
                                packet_callback=update_traffic_ui, 
                                count=pkt_count)
                            st.success(f"Capture finished. Collected {len(captured_data)} packets.")
                            
                            if captured_data:
                                # --- EXPORT TO CSV FEATURE ---
                                df_final = pd.DataFrame(captured_data)
                                csv_data = df_final.to_csv(index=False).encode('utf-8')
                                
                                st.download_button(
                                    label="Export Traffic Log (CSV)",
                                    data=csv_data,
                                    file_name="NetworkTraffic_Log.csv",
                                    mime="text/csv",
                                    use_container_width=True
                                )
                            else:
                                traffic_placeholder.warning("No packets captured. Check your filter or network activity.")
                        except Exception as e:
                            st.error(f"Capture failed: {e}")