import streamlit as st
import sys
import os
import nltk

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
    .stSelectbox > div > div > div {
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
        font-weight: 600;
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

# --- 5. TABS NAVIGATION ---
tab_strength, tab_gen, tab_web = st.tabs(["Password Strength Analyzer", "Secure Password Generator", "Web Form Validator"])

# ==========================================
# TAB 1: PASSWORD STRENGTH
# ==========================================
with tab_strength:
    # centered layour using columns
    c_left, c_center, c_right = st.columns([1, 2, 1])
    
    with c_center:
        st.markdown("### Password Strength")
        st.caption("Enter a password to analyze its complexity and entropy.")
        
        password = st.text_input("Password", type="password", key="strength_input", label_visibility="collapsed", placeholder="Type your password here...")
        
        if st.button("Analyze Strength", key="btn_strength"):
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
                st.info("Please input a password first.")

# ==========================================
# TAB 2: PASSWORD GENERATOR
# ==========================================
with tab_gen:
    
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

# ==========================================
# TAB 3: WEB VALIDATOR
# ==========================================
with tab_web:
    
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
                
                # Show the before/after or just the final clean result
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