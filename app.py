#!/usr/bin/env python3
"""
Domain Intelligence - Streamlit Web Interface

A modern web UI for the Domain Intelligence security scanner.
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime, timedelta
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import os
import pandas as pd
import json

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner import Scanner
from src.core.config import Config
from src.core.domain import DomainResult, Severity
from src.core.database import db, Database
from src.core.errors import ErrorCodes, format_error
from src.core.validation import DomainValidator, validate_domains
from src.core.notifications import notification_service

# Constants
SESSION_TIMEOUT_MINUTES = 30
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

# Page configuration
st.set_page_config(
    page_title="Domain Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Scroll to top function
def scroll_to_top():
    """Inject JavaScript to scroll to top of page."""
    st.markdown("""
        <script>
            window.scrollTo({top: 0, behavior: 'smooth'});
        </script>
    """, unsafe_allow_html=True)

# Handle scroll request
if st.session_state.get('scroll_to_top', False):
    scroll_to_top()
    st.session_state.scroll_to_top = False

# Custom CSS - Light Cyber Security Theme
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
    }
    
    /* Force dark text globally */
    .stApp, .stApp p, .stApp span, .stApp div, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
        color: #1a202c !important;
    }
    
    /* Text inputs */
    .stTextInput input, .stTextArea textarea, .stSelectbox select {
        color: #1a202c !important;
        background-color: #ffffff !important;
    }
    
    /* Selectbox / Dropdown styling */
    .stSelectbox > div > div {
        background-color: #ffffff !important;
        color: #1a202c !important;
    }
    .stSelectbox [data-baseweb="select"] {
        background-color: #ffffff !important;
    }
    .stSelectbox [data-baseweb="select"] * {
        color: #1a202c !important;
    }
    [data-baseweb="popover"] {
        background-color: #ffffff !important;
    }
    [data-baseweb="popover"] * {
        color: #1a202c !important;
        background-color: #ffffff !important;
    }
    [data-baseweb="menu"] {
        background-color: #ffffff !important;
    }
    [data-baseweb="menu"] * {
        color: #1a202c !important;
    }
    [role="listbox"] {
        background-color: #ffffff !important;
    }
    [role="listbox"] * {
        color: #1a202c !important;
    }
    [role="option"] {
        background-color: #ffffff !important;
        color: #1a202c !important;
    }
    [role="option"]:hover {
        background-color: #e2e8f0 !important;
    }
    
    /* Multiselect styling */
    .stMultiSelect [data-baseweb="tag"] {
        background-color: #00d4aa !important;
        color: white !important;
    }
    
    /* Header / App header */
    header[data-testid="stHeader"] {
        background-color: #ffffff !important;
    }
    
    /* Main container */
    .main .block-container {
        background-color: transparent !important;
    }
    
    /* DataFrame / Table styling - Force light theme */
    .stDataFrame, .stDataFrame > div {
        background-color: #ffffff !important;
    }
    [data-testid="stDataFrame"] {
        background-color: #ffffff !important;
    }
    [data-testid="stDataFrame"] * {
        color: #1a202c !important;
    }
    [data-testid="stDataFrame"] div[data-testid="stDataFrameResizable"] {
        background-color: #ffffff !important;
    }
    .dvn-scroller {
        background-color: #ffffff !important;
    }
    
    /* Glide Data Grid styling for dataframes */
    .gdg-style, .dvn-underlay, .dvn-scroller, canvas {
        background-color: #ffffff !important;
    }
    [data-testid="glideDataEditor"] {
        background-color: #ffffff !important;
    }
    [data-testid="stDataFrame"] canvas {
        background-color: #ffffff !important;
    }
    
    /* Table header and cell styling */
    .stDataFrame th, .stDataFrame td {
        background-color: #ffffff !important;
        color: #1a202c !important;
    }
    .stDataFrame thead tr {
        background-color: #f7fafc !important;
    }
    .stDataFrame tbody tr {
        background-color: #ffffff !important;
    }
    .stDataFrame tbody tr:hover {
        background-color: #f0f4f8 !important;
    }
    
    /* Markdown text */
    .stMarkdown, .stMarkdown p, .stMarkdown span, .stMarkdown div {
        color: #1a202c !important;
    }
    
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(90deg, #00d4aa, #00a8cc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #1a202c !important;
        margin-top: 0;
        font-weight: 500;
    }
    .metric-card {
        background: linear-gradient(135deg, #00d4aa 0%, #00a8cc 100%);
        padding: 1rem;
        border-radius: 12px;
        color: white !important;
        box-shadow: 0 4px 15px rgba(0, 212, 170, 0.3);
    }
    .metric-card * {
        color: white !important;
    }
    .severity-critical { color: #c53030 !important; font-weight: bold; }
    .severity-high { color: #c05621 !important; font-weight: bold; }
    .severity-medium { color: #b7791f !important; font-weight: bold; }
    .severity-low { color: #0987a0 !important; }
    .severity-info { color: #4a5568 !important; }
    .finding-card {
        border-left: 4px solid;
        padding: 1rem 1.2rem;
        margin: 0.8rem 0;
        background: linear-gradient(135deg, #ffffff 0%, #f7fafc 100%);
        border-radius: 0 12px 12px 0;
        color: #1a202c !important;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .finding-card * {
        color: #1a202c !important;
    }
    .finding-card:hover {
        transform: translateX(5px);
        box-shadow: 0 4px 20px rgba(0, 212, 170, 0.15);
    }
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #00d4aa, #00a8cc);
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #ffffff 0%, #f7fafc 100%);
        border-right: 1px solid #e2e8f0;
    }
    [data-testid="stSidebar"] *, 
    [data-testid="stSidebar"] p, 
    [data-testid="stSidebar"] span, 
    [data-testid="stSidebar"] div,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 {
        color: #1a202c !important;
    }
    [data-testid="stSidebar"] .stCheckbox label {
        color: #1a202c !important;
    }
    [data-testid="stSidebar"] input {
        color: #1a202c !important;
        background-color: #ffffff !important;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(90deg, #00d4aa, #00a8cc);
        color: white !important;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 0.6rem 1.5rem;
        transition: all 0.3s;
        box-shadow: 0 4px 15px rgba(0, 212, 170, 0.3);
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0, 212, 170, 0.4);
        color: white !important;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 12px;
        flex-wrap: wrap;
    }
    .stTabs [data-baseweb="tab"] {
        background: #f7fafc;
        border-radius: 8px 8px 0 0;
        border: 1px solid #e2e8f0;
        color: #1a202c !important;
        padding: 12px 24px !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        min-width: 120px !important;
        white-space: nowrap !important;
    }
    .stTabs [data-baseweb="tab"] > div {
        font-size: 1rem !important;
        padding: 0 !important;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(90deg, #00d4aa, #00a8cc);
        color: white !important;
    }
    .stTabs [aria-selected="true"] * {
        color: white !important;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%) !important;
        border-radius: 8px;
        font-weight: 600;
        color: #1a202c !important;
    }
    [data-testid="stExpander"] {
        background-color: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
    }
    [data-testid="stExpander"] summary {
        background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%) !important;
        color: #1a202c !important;
        padding: 12px 16px !important;
    }
    [data-testid="stExpander"] summary * {
        color: #1a202c !important;
    }
    [data-testid="stExpander"] summary:hover {
        background: linear-gradient(135deg, #edf2f7 0%, #e2e8f0 100%) !important;
    }
    [data-testid="stExpander"] div[data-testid="stExpanderDetails"] {
        background-color: #ffffff !important;
        color: #1a202c !important;
    }
    .streamlit-expanderContent {
        color: #1a202c !important;
    }
    
    /* Data table styling */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        background-color: #ffffff !important;
    }
    .stDataFrame * {
        color: #1a202c !important;
        background-color: #ffffff !important;
    }
    .stDataFrame th {
        background-color: #f7fafc !important;
        color: #1a202c !important;
    }
    .stDataFrame td {
        background-color: #ffffff !important;
        color: #1a202c !important;
    }
    
    /* Code blocks */
    .stCode, code, pre {
        background-color: #f7fafc !important;
        color: #1a202c !important;
    }
    
    /* Download button styling */
    .stDownloadButton > button {
        background: linear-gradient(90deg, #00d4aa, #00a8cc) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 0.5rem 1rem !important;
    }
    .stDownloadButton > button:hover {
        background: linear-gradient(90deg, #00c49a, #0098bc) !important;
        color: white !important;
    }
    .stDownloadButton > button * {
        color: white !important;
    }
    
    /* Info, success, warning, error boxes */
    .stAlert {
        color: #1a202c !important;
    }
    .stAlert * {
        color: #1a202c !important;
    }
    
    /* Metric values */
    [data-testid="stMetricValue"] {
        color: #1a202c !important;
    }
    [data-testid="stMetricLabel"] {
        color: #4a5568 !important;
    }
    
    /* Login card */
    .login-card {
        background: white;
        padding: 2rem;
        border-radius: 16px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
        max-width: 400px;
        margin: 2rem auto;
    }
    
    /* Navigation menu */
    .nav-item {
        padding: 0.8rem 1rem;
        margin: 0.3rem 0;
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s;
    }
    .nav-item:hover {
        background: rgba(255,255,255,0.1);
    }
    .nav-item.active {
        background: linear-gradient(90deg, #00d4aa, #00a8cc);
    }
</style>
""", unsafe_allow_html=True)


# ============== UTILITY FUNCTIONS ==============

def get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "#dc3545",
        "high": "#fd7e14", 
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d"
    }
    return colors.get(severity, "#6c757d")


def get_severity_emoji(severity: str) -> str:
    """Get emoji for severity level."""
    emojis = {
        "critical": "",
        "high": "",
        "medium": "",
        "low": "",
        "info": ""
    }
    return emojis.get(severity, "")


def check_session_timeout():
    """Check if session has timed out."""
    if 'last_activity' in st.session_state:
        last_activity = st.session_state.last_activity
        if datetime.now() - last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            # Session expired
            if 'session_id' in st.session_state and st.session_state.session_id:
                db.invalidate_session(st.session_state.session_id)
            st.session_state.authenticated = False
            st.session_state.session_id = None
            st.session_state.user_id = None
            return True
    # Update last activity
    st.session_state.last_activity = datetime.now()
    return False


def init_session_state():
    """Initialize session state variables."""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = ""
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'user_role' not in st.session_state:
        st.session_state.user_role = "user"
    if 'session_id' not in st.session_state:
        st.session_state.session_id = None
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.now()
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None
    if 'scanning' not in st.session_state:
        st.session_state.scanning = False
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "scan"
    if 'login_error' not in st.session_state:
        st.session_state.login_error = None


# ============== LOGIN SCREEN ==============

def render_login():
    """Render login screen with rate limiting and proper authentication."""
    st.markdown("")
    st.markdown("")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<p class="main-header" style="text-align: center;">Domain Intelligence</p>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header" style="text-align: center;">Security Assessment Platform</p>', unsafe_allow_html=True)
        
        st.markdown("")
        st.markdown("")
        
        with st.container():
            st.markdown("### Login")
            
            # Show any login errors
            if st.session_state.get('login_error'):
                st.error(st.session_state.login_error)
                st.session_state.login_error = None
            
            username = st.text_input("Username", placeholder="Enter your username", key="login_username")
            password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password")
            
            st.markdown("")
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("Login", type="primary", use_container_width=True):
                    if username and password:
                        # Check rate limiting
                        if db.is_rate_limited(username, MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_MINUTES):
                            locked, locked_until = db.is_account_locked(username)
                            if locked and locked_until:
                                mins_remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                                st.session_state.login_error = format_error(ErrorCodes.with_details(
                                    ErrorCodes.AUTH_RATE_LIMITED,
                                    f"Try again in {mins_remaining} minutes"
                                ))
                            else:
                                st.session_state.login_error = format_error(ErrorCodes.AUTH_RATE_LIMITED)
                            db.record_login_attempt(username, None, False)
                            st.rerun()
                        
                        # Verify credentials with database
                        user = db.verify_user(username, password)
                        
                        if user:
                            # Successful login
                            session_id = db.create_session(user.id, duration_hours=8)
                            db.record_login_attempt(username, None, True)
                            db.log_audit(user.id, "LOGIN", "User logged in successfully")
                            
                            st.session_state.authenticated = True
                            st.session_state.username = user.username
                            st.session_state.user_id = user.id
                            st.session_state.user_role = user.role
                            st.session_state.session_id = session_id
                            st.session_state.last_activity = datetime.now()
                            st.rerun()
                        else:
                            # Failed login
                            db.record_login_attempt(username, None, False)
                            
                            # Check if account is now locked
                            locked, locked_until = db.is_account_locked(username)
                            if locked:
                                st.session_state.login_error = format_error(ErrorCodes.AUTH_ACCOUNT_LOCKED)
                            else:
                                attempts = db.get_recent_login_attempts(username, LOGIN_LOCKOUT_MINUTES)
                                remaining = MAX_LOGIN_ATTEMPTS - attempts
                                st.session_state.login_error = format_error(ErrorCodes.with_details(
                                    ErrorCodes.AUTH_INVALID_CREDENTIALS,
                                    f"{remaining} attempts remaining"
                                ))
                            st.rerun()
                    else:
                        st.warning(format_error(ErrorCodes.VALID_MISSING_REQUIRED))
            
            with col_btn2:
                if st.button("Guest Access", use_container_width=True):
                    st.session_state.authenticated = True
                    st.session_state.username = "Guest"
                    st.session_state.user_id = None
                    st.session_state.user_role = "guest"
                    st.session_state.last_activity = datetime.now()
                    db.log_audit(None, "GUEST_LOGIN", "Guest user logged in")
                    st.rerun()
            
            st.markdown("")
            st.caption("Default credentials: admin / admin123")


# ============== SIDEBAR NAVIGATION ==============

def render_sidebar():
    """Render sidebar navigation."""
    st.sidebar.markdown("### Domain Intelligence")
    st.sidebar.markdown(f"Welcome, **{st.session_state.username}**")
    
    # Show session timeout warning
    if 'last_activity' in st.session_state:
        elapsed = (datetime.now() - st.session_state.last_activity).total_seconds() / 60
        remaining = SESSION_TIMEOUT_MINUTES - elapsed
        if remaining < 5:
            st.sidebar.warning(f"Session expires in {int(remaining)} min")
    
    st.sidebar.divider()
    
    # Navigation
    st.sidebar.markdown("### Navigation")
    
    if st.sidebar.button("Domain Scan", use_container_width=True, 
                         type="primary" if st.session_state.current_page == "scan" else "secondary"):
        st.session_state.current_page = "scan"
        st.session_state.scroll_to_top = True
        st.rerun()
    
    if st.sidebar.button("Scan Results", use_container_width=True,
                         type="primary" if st.session_state.current_page == "results" else "secondary"):
        st.session_state.current_page = "results"
        st.session_state.scroll_to_top = True
        st.rerun()
    
    if st.sidebar.button("Scan History", use_container_width=True,
                         type="primary" if st.session_state.current_page == "history" else "secondary"):
        st.session_state.current_page = "history"
        st.session_state.scroll_to_top = True
        st.rerun()
    
    if st.sidebar.button("Reports", use_container_width=True,
                         type="primary" if st.session_state.current_page == "reports" else "secondary"):
        st.session_state.current_page = "reports"
        st.session_state.scroll_to_top = True
        st.rerun()
    
    if st.sidebar.button("Email Reports", use_container_width=True,
                         type="primary" if st.session_state.current_page == "email" else "secondary"):
        st.session_state.current_page = "email"
        st.session_state.scroll_to_top = True
        st.rerun()
    
    if st.sidebar.button("Webhooks", use_container_width=True,
                         type="primary" if st.session_state.current_page == "webhooks" else "secondary"):
        st.session_state.current_page = "webhooks"
        st.session_state.scroll_to_top = True
        st.rerun()
    
    st.sidebar.divider()
    
    # Logout
    if st.sidebar.button("Logout", use_container_width=True):
        if st.session_state.get('session_id'):
            db.invalidate_session(st.session_state.session_id)
            db.log_audit(st.session_state.get('user_id'), "LOGOUT", "User logged out")
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.user_id = None
        st.session_state.session_id = None
        st.session_state.scan_results = None
        st.rerun()
    
    # Return default settings
    enabled_modules = {
        "ct_enumeration": True,
        "dns_enumeration": True,
        "tls_inspection": True,
        "whois_lookup": True,
        "ssllabs": True,
        "redirect_analysis": True,
        "takeover_detection": True,
        "virustotal": False,
        "abuseipdb": False,
        "alienvault_otx": False,
        "criminalip": False,
        "urlscan": False,
    }
    
    return enabled_modules, 5, ["json", "csv", "html"]


# ============== SCAN FUNCTIONS ==============

def run_scan(domains: list, enabled_modules: dict, workers: int, output_formats: list, user_id: int = None):
    """Run the domain scan with database logging and webhook notifications."""
    scan_id = None
    start_time = time.time()
    
    try:
        # Create scan record in database
        if user_id:
            scan_id = db.create_scan(user_id, domains)
            db.log_audit(user_id, "SCAN_STARTED", f"Started scan of {len(domains)} domain(s)")
        
        config = Config()
        
        for module, enabled in enabled_modules.items():
            if module in config._config.get("modules", {}):
                config._config["modules"][module]["enabled"] = enabled
        
        config._config["execution"] = config._config.get("execution", {})
        config._config["execution"]["max_workers"] = workers
        
        config._config["output"] = config._config.get("output", {})
        config._config["output"]["formats"] = output_formats
        
        scanner = Scanner(config)
        results = scanner.scan_domains(domains)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Generate reports after scan
        if results:
            scanner.generate_reports(results, output_formats)
            
            # Calculate severity breakdown
            severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            total_findings = 0
            for result in results:
                for finding in result.findings:
                    sev = finding.severity.value.lower()
                    severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
                    total_findings += 1
            
            # Update scan record
            if scan_id and user_id:
                scan_data = {
                    "domains_scanned": [r.domain for r in results],
                    "modules_executed": list(set(m for r in results for m in r.modules_executed))
                }
                db.update_scan(
                    scan_id, 
                    status="completed",
                    total_findings=total_findings,
                    severity_breakdown=severity_breakdown,
                    scan_data=scan_data,
                    duration_seconds=duration
                )
                db.log_audit(user_id, "SCAN_COMPLETED", f"Scan completed with {total_findings} findings")
            
            # Send webhook notifications
            if user_id:
                webhooks = db.get_user_webhooks(user_id)
                if webhooks:
                    notification_data = {
                        "domains": domains,
                        "total_findings": total_findings,
                        "severity_breakdown": severity_breakdown,
                        "duration_seconds": duration
                    }
                    notification_service.notify_scan_complete(webhooks, notification_data)
        
        return results
        
    except Exception as e:
        # Update scan record with failure
        if scan_id and user_id:
            db.update_scan(scan_id, status="failed", duration_seconds=time.time() - start_time)
            db.log_audit(user_id, "SCAN_FAILED", str(e))
        
        st.error(format_error(ErrorCodes.with_details(ErrorCodes.SCAN_FAILED, str(e))))
        return None


# ============== PAGE: DOMAIN SCAN ==============

def render_scan_page(enabled_modules, workers, output_formats):
    """Render domain scan page."""
    st.markdown('<p class="main-header">Domain Scan</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Enter domains to analyze for security vulnerabilities</p>', unsafe_allow_html=True)
    
    st.divider()
    
    # Domain input section
    st.markdown("### Target Domains")
    
    input_method = st.radio(
        "Input Method",
        ["Single Domain", "Multiple Domains", "Upload File"],
        horizontal=True
    )
    
    raw_domains = []
    
    if input_method == "Single Domain":
        domain = st.text_input("Enter domain to scan", placeholder="example.com")
        if domain:
            raw_domains = [domain.strip()]
    
    elif input_method == "Multiple Domains":
        domain_text = st.text_area(
            "Enter domains (one per line)",
            placeholder="example.com\nexample.org\nexample.net",
            height=150
        )
        if domain_text:
            raw_domains = [d.strip() for d in domain_text.split("\n") if d.strip()]
    
    else:
        uploaded_file = st.file_uploader("Upload domain list", type=["txt"])
        if uploaded_file:
            content = uploaded_file.read().decode("utf-8")
            raw_domains = [d.strip() for d in content.split("\n") if d.strip()]
            st.success(f"Loaded {len(raw_domains)} domains from file")
    
    # Validate domains
    domains = []
    validation_errors = []
    
    if raw_domains:
        domains, validation_errors = validate_domains(raw_domains)
        
        if validation_errors:
            st.warning(f"Found {len(validation_errors)} invalid domain(s):")
            with st.expander("Show validation errors", expanded=False):
                for error in validation_errors[:10]:
                    st.markdown(f"- {error}")
                if len(validation_errors) > 10:
                    st.markdown(f"... and {len(validation_errors) - 10} more errors")
        
        if domains:
            st.info(f"Ready to scan {len(domains)} valid domain(s): {', '.join(domains[:5])}{'...' if len(domains) > 5 else ''}")
        else:
            st.error(format_error(ErrorCodes.VALID_INVALID_DOMAIN))
    
    st.divider()
    
    # Report format selection
    st.markdown("### Report Formats")
    st.markdown("Select the formats for generated reports:")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        fmt_json = st.checkbox("JSON", value=True, help="Machine-readable format")
    with col2:
        fmt_csv = st.checkbox("CSV", value=True, help="Spreadsheet compatible")
    with col3:
        fmt_html = st.checkbox("HTML", value=True, help="Human-readable report")
    
    selected_formats = []
    if fmt_json:
        selected_formats.append("json")
    if fmt_csv:
        selected_formats.append("csv")
    if fmt_html:
        selected_formats.append("html")
    
    if not selected_formats:
        st.warning("Please select at least one report format")
    
    st.divider()
    
    # Scan button
    if st.button("Start Scan", type="primary", disabled=not domains or not selected_formats, use_container_width=True):
        with st.spinner(f"Scanning {len(domains)} domain(s)... This may take a few minutes."):
            progress_bar = st.progress(0, text="Initializing scanner...")
            
            # Pass user_id for database logging
            user_id = st.session_state.get('user_id')
            results = run_scan(domains, enabled_modules, workers, selected_formats, user_id)
            
            progress_bar.progress(100, text="Scan complete!")
            
            if results:
                st.session_state.scan_results = results
                st.session_state.scan_just_completed = True
                st.rerun()
    
    # Show navigation options after scan completes
    if st.session_state.get('scan_just_completed', False):
        st.success(f"Scan complete! Found {sum(len(r.findings) for r in st.session_state.scan_results)} findings across {len(st.session_state.scan_results)} domain(s).")
        
        st.markdown("### Next Steps")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("View Results", type="primary", use_container_width=True, key="nav_results"):
                st.session_state.scan_just_completed = False
                st.session_state.current_page = "results"
                st.session_state.scroll_to_top = True
                st.rerun()
        with col2:
            if st.button("View Reports", type="secondary", use_container_width=True, key="nav_reports"):
                st.session_state.scan_just_completed = False
                st.session_state.current_page = "reports"
                st.session_state.scroll_to_top = True
                st.rerun()


# ============== PAGE: SCAN RESULTS ==============

def render_results_page():
    """Render scan results page."""
    st.markdown('<p class="main-header">Scan Results</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Detailed analysis of scanned domains</p>', unsafe_allow_html=True)
    
    st.divider()
    
    results = st.session_state.scan_results
    
    if not results:
        st.info("No scan results available. Go to Domain Scan to start a new scan.")
        return
    
    # Summary metrics
    st.markdown("### Summary")
    
    total_findings = sum(len(r.findings) for r in results)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity.value] += 1
    
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    
    with col1:
        st.metric("Domains", len(results))
    with col2:
        st.metric("Total Findings", total_findings)
    with col3:
        st.metric("Critical", severity_counts["critical"])
    with col4:
        st.metric("High", severity_counts["high"])
    with col5:
        st.metric("Medium", severity_counts["medium"])
    with col6:
        st.metric("Low", severity_counts["low"])
    
    st.divider()
    
    # Domain selector
    st.markdown("### Domain Details")
    
    domain_names = [r.domain for r in results]
    selected_domain = st.selectbox("Select Domain", domain_names)
    
    # Get selected result
    selected_result = next((r for r in results if r.domain == selected_domain), None)
    
    if selected_result:
        st.markdown(f"**Domain:** {selected_result.domain}")
        st.markdown(f"**Severity Score:** {selected_result.severity_score}")
        st.markdown(f"**Total Findings:** {len(selected_result.findings)}")
        
        # Tabs for different data
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["Findings", "DNS Records", "TLS Certificate", "WHOIS", "Subdomains"])
        
        with tab1:
            if selected_result.findings:
                for finding in sorted(selected_result.findings, key=lambda f: f.severity, reverse=True):
                    sev = finding.severity.value
                    emoji = get_severity_emoji(sev)
                    color = get_severity_color(sev)
                    
                    st.markdown(f"""
                    <div class="finding-card" style="border-left-color: {color};">
                        <strong>{emoji} {sev.upper()}</strong> - {finding.title}<br>
                        <small style="color: #718096;">{finding.description}</small>
                        {f'<br><code style="font-size: 0.8rem; color: #2d3748; background: #edf2f7; padding: 0.2rem 0.4rem; border-radius: 4px;">{finding.evidence[:200]}...</code>' if finding.evidence and len(finding.evidence) > 200 else f'<br><code style="font-size: 0.8rem; color: #2d3748; background: #edf2f7; padding: 0.2rem 0.4rem; border-radius: 4px;">{finding.evidence}</code>' if finding.evidence else ''}
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("No security findings for this domain")
        
        with tab2:
            if selected_result.dns_records:
                st.write(f"Found {len(selected_result.dns_records)} DNS records:")
                # Build HTML table for better styling control
                table_html = """
                <table style="width: 100%; border-collapse: collapse; background-color: #ffffff; color: #1a202c;">
                    <thead>
                        <tr style="background-color: #f7fafc; border-bottom: 2px solid #e2e8f0;">
                            <th style="padding: 12px; text-align: left; color: #1a202c; font-weight: 600;">Type</th>
                            <th style="padding: 12px; text-align: left; color: #1a202c; font-weight: 600;">Value</th>
                            <th style="padding: 12px; text-align: left; color: #1a202c; font-weight: 600;">TTL</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for record in selected_result.dns_records:
                    table_html += f"""
                        <tr style="border-bottom: 1px solid #e2e8f0;">
                            <td style="padding: 10px; color: #1a202c; background-color: #ffffff;">{record.record_type}</td>
                            <td style="padding: 10px; color: #1a202c; background-color: #ffffff; word-break: break-all;">{record.value}</td>
                            <td style="padding: 10px; color: #1a202c; background-color: #ffffff;">{record.ttl if record.ttl else 'N/A'}</td>
                        </tr>
                    """
                table_html += "</tbody></table>"
                st.markdown(table_html, unsafe_allow_html=True)
            else:
                st.info("No DNS records found")
        
        with tab3:
            if selected_result.tls_certificate:
                cert = selected_result.tls_certificate
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Subject:** {cert.subject_cn}")
                    st.markdown(f"**Issuer:** {cert.issuer}")
                    st.markdown(f"**Serial:** {cert.serial_number}")
                with col2:
                    st.markdown(f"**Valid From:** {cert.not_before}")
                    st.markdown(f"**Valid Until:** {cert.not_after}")
                    status = "Expired" if cert.is_expired else f"Valid ({cert.days_until_expiry} days)"
                    st.markdown(f"**Status:** {status}")
                
                if cert.san:
                    st.markdown("**SAN Domains:**")
                    st.code(", ".join(cert.san[:20]))
            else:
                st.info("No TLS certificate information")
        
        with tab4:
            if selected_result.whois_info:
                whois = selected_result.whois_info
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Registrar:** {whois.registrar or 'N/A'}")
                    st.markdown(f"**Registrant:** {whois.registrant_org or 'N/A'}")
                    st.markdown(f"**Country:** {whois.registrant_country or 'N/A'}")
                with col2:
                    st.markdown(f"**Created:** {whois.creation_date or 'N/A'}")
                    st.markdown(f"**Expires:** {whois.expiration_date or 'N/A'}")
                    st.markdown(f"**Domain Age:** {whois.domain_age_days or 'N/A'} days")
            else:
                st.info("No WHOIS information")
        
        with tab5:
            if selected_result.subdomains:
                st.markdown(f"**Found {len(selected_result.subdomains)} subdomains:**")
                subdomain_list = sorted(selected_result.subdomains)[:100]
                
                cols = st.columns(3)
                for i, subdomain in enumerate(subdomain_list):
                    cols[i % 3].markdown(f"• {subdomain}")
                
                if len(selected_result.subdomains) > 100:
                    st.info(f"... and {len(selected_result.subdomains) - 100} more subdomains")
            else:
                st.info("No subdomains discovered")


# ============== PAGE: REPORTS ==============

def render_reports_page():
    """Render reports page."""
    st.markdown('<p class="main-header">Reports</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Download and manage generated reports</p>', unsafe_allow_html=True)
    
    st.divider()
    
    output_dir = Path("output")
    
    if not output_dir.exists():
        st.info("No reports directory found. Run a scan to generate reports.")
        return
    
    reports = list(output_dir.glob("domain_intel_*"))
    
    if not reports:
        st.info("No reports generated yet. Run a scan to generate reports.")
        return
    
    # Sort by modification time (newest first)
    reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    # Group reports by scan timestamp
    scan_groups = {}
    for report in reports:
        # Extract timestamp from filename
        parts = report.stem.split("_")
        if len(parts) >= 3:
            timestamp = "_".join(parts[2:4]) if len(parts) >= 4 else parts[2]
            if timestamp not in scan_groups:
                scan_groups[timestamp] = []
            scan_groups[timestamp].append(report)
    
    st.markdown("### Available Reports")
    
    for timestamp, files in scan_groups.items():
        with st.expander(f"Scan: {timestamp}", expanded=True):
            for report in files:
                col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
                
                with col1:
                    file_type = report.suffix.upper()[1:]
                    st.markdown(f"**{report.name}**")
                
                with col2:
                    st.markdown(f"{report.stat().st_size / 1024:.1f} KB")
                
                with col3:
                    mod_time = datetime.fromtimestamp(report.stat().st_mtime)
                    st.markdown(mod_time.strftime("%H:%M:%S"))
                
                with col4:
                    with open(report, "rb") as f:
                        st.download_button(
                            "Download",
                            f.read(),
                            file_name=report.name,
                            key=f"dl_{report.name}",
                            use_container_width=True
                        )
    
    st.divider()
    
    # Clear reports option
    st.markdown("### Manage Reports")
    if st.button("Clear All Reports", type="secondary"):
        for report in reports:
            report.unlink()
        st.success("All reports cleared!")
        st.rerun()


# ============== PAGE: EMAIL REPORTS ==============

def render_email_page():
    """Render email reports page."""
    st.markdown('<p class="main-header">Email Reports</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Share reports via email</p>', unsafe_allow_html=True)
    
    st.divider()
    
    # Load SMTP config from backend
    email_config = config.get('email', {})
    smtp_server = email_config.get('smtp_server', '')
    smtp_port = email_config.get('smtp_port', 587)
    sender_email = email_config.get('sender_email', '')
    sender_password = email_config.get('sender_password', '')
    
    # Check if SMTP is configured
    if not smtp_server or not sender_email or not sender_password:
        st.warning("⚠️ Email is not configured. Please configure SMTP settings in `config.yaml`.")
        st.code("""# config.yaml
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  sender_email: "your.email@gmail.com"
  sender_password: "your-app-password"
  use_tls: true""", language="yaml")
        st.info("For Gmail, use an App Password instead of your regular password.")
        return
    
    # Get available reports
    output_dir = Path("output")
    reports = []
    if output_dir.exists():
        reports = list(output_dir.glob("domain_intel_*"))
        reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    if not reports:
        st.info("No reports available to share. Run a scan first to generate reports.")
        return
    
    # Show configured sender (masked)
    st.markdown("### Email Configuration")
    st.info(f"📧 Sending from: **{sender_email}** (configured in config.yaml)")
    
    # Recipient email input
    recipient_email = st.text_input("Recipient Email", placeholder="recipient@example.com")
    
    st.divider()
    
    # Report selection
    st.markdown("### Select Reports to Send")
    
    report_names = [r.name for r in reports[:20]]  # Limit to last 20 reports
    selected_reports = st.multiselect(
        "Choose reports to attach",
        report_names,
        default=report_names[:3] if len(report_names) >= 3 else report_names
    )
    
    st.divider()
    
    # Email content
    st.markdown("### Email Content")
    
    email_subject = st.text_input(
        "Subject",
        value=f"Domain Intelligence Security Report - {datetime.now().strftime('%Y-%m-%d')}"
    )
    
    email_body = st.text_area(
        "Message",
        value="""Hello,

Please find attached the Domain Intelligence security scan reports.

Summary:
- Reports generated on: {date}
- Number of attachments: {num_attachments}

This is an automated report from Domain Intelligence Security Assessment Platform.

Best regards,
Security Team""".format(
            date=datetime.now().strftime('%Y-%m-%d %H:%M'),
            num_attachments=len(selected_reports)
        ),
        height=200
    )
    
    st.divider()
    
    # Send button
    col_send, col_test = st.columns(2)
    
    with col_send:
        send_clicked = st.button("Send Email", type="primary", use_container_width=True, key="send_email_btn")
    
    with col_test:
        test_clicked = st.button("Test Connection", type="secondary", use_container_width=True, key="test_conn_btn")
    
    # Test connection
    if test_clicked:
        try:
            with st.spinner("Testing SMTP connection..."):
                with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
                    server.starttls()
                    server.login(sender_email, sender_password)
                st.success("✅ Connection successful! SMTP settings in config.yaml are correct.")
        except smtplib.SMTPAuthenticationError:
            st.error("❌ Authentication failed. Check email and password in config.yaml. For Gmail, use an App Password.")
        except smtplib.SMTPConnectError:
            st.error(f"❌ Could not connect to {smtp_server}:{smtp_port}. Check server and port in config.yaml.")
        except Exception as e:
            st.error(f"❌ Connection failed: {str(e)}")
    
    # Send email
    if send_clicked:
        if not recipient_email:
            st.error("Please enter a recipient email address.")
        elif not selected_reports:
            st.error("Please select at least one report to send.")
            st.error("Please select at least one report to send.")
        else:
            try:
                with st.spinner("Sending email..."):
                    # Create message
                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = recipient_email
                    msg['Subject'] = email_subject
                    
                    # Add body
                    msg.attach(MIMEText(email_body, 'plain'))
                    
                    # Add attachments
                    attached_count = 0
                    for report_name in selected_reports:
                        report_path = output_dir / report_name
                        if report_path.exists():
                            with open(report_path, "rb") as f:
                                part = MIMEBase('application', 'octet-stream')
                                part.set_payload(f.read())
                                encoders.encode_base64(part)
                                part.add_header(
                                    'Content-Disposition',
                                    f'attachment; filename={report_name}'
                                )
                                msg.attach(part)
                                attached_count += 1
                    
                    # Send email
                    with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
                        server.starttls()
                        server.login(sender_email, sender_password)
                        server.send_message(msg)
                    
                    st.success(f"Email sent successfully to {recipient_email} with {attached_count} attachment(s)!")
                    db.log_audit(st.session_state.get('user_id'), "EMAIL_SENT", f"Report sent to {recipient_email}")
                    
            except smtplib.SMTPAuthenticationError:
                st.error(format_error(ErrorCodes.EMAIL_AUTH_FAILED))
                st.info("Check your email credentials in config.yaml. For Gmail, use an App Password.")
            except smtplib.SMTPConnectError:
                st.error(format_error(ErrorCodes.with_details(ErrorCodes.EMAIL_CONNECTION_FAILED, f"{smtp_server}:{smtp_port}")))
                st.info("Check SMTP server and port settings in config.yaml.")
            except Exception as e:
                st.error(format_error(ErrorCodes.with_details(ErrorCodes.EMAIL_SEND_FAILED, str(e))))


# ============== PAGE: SCAN HISTORY ==============

def render_history_page():
    """Render scan history page."""
    st.markdown('<p class="main-header">Scan History</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">View past scan results and statistics</p>', unsafe_allow_html=True)
    
    st.divider()
    
    user_id = st.session_state.get('user_id')
    user_role = st.session_state.get('user_role', 'user')
    
    if not user_id:
        st.info("Login required to view scan history. Guest users don't have scan history.")
        return
    
    # Get scans based on role
    if user_role == 'admin':
        scans = db.get_all_scans(limit=100)
        st.markdown("### All Scans (Admin View)")
    else:
        scans = db.get_user_scans(user_id, limit=50)
        st.markdown("### Your Scans")
    
    if not scans:
        st.info("No scan history found. Run a scan to see it here.")
        return
    
    # Summary stats
    col1, col2, col3, col4 = st.columns(4)
    
    total_scans = len(scans)
    completed_scans = len([s for s in scans if s.status == 'completed'])
    total_findings = sum(s.total_findings for s in scans)
    critical_findings = sum(s.severity_breakdown.get('critical', 0) for s in scans)
    
    with col1:
        st.metric("Total Scans", total_scans)
    with col2:
        st.metric("Completed", completed_scans)
    with col3:
        st.metric("Total Findings", total_findings)
    with col4:
        st.metric("Critical", critical_findings)
    
    st.divider()
    
    # Scan list
    for scan in scans:
        status_color = {
            'completed': '#28a745',
            'running': '#ffc107',
            'failed': '#dc3545',
            'pending': '#6c757d'
        }.get(scan.status, '#6c757d')
        
        created_at = scan.created_at if isinstance(scan.created_at, datetime) else datetime.fromisoformat(str(scan.created_at))
        
        with st.expander(f"Scan #{scan.id} - {', '.join(scan.domains[:3])}{'...' if len(scan.domains) > 3 else ''}", expanded=False):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Status:** <span style='color: {status_color}; font-weight: bold;'>{scan.status.upper()}</span>", unsafe_allow_html=True)
                st.markdown(f"**Domains:** {', '.join(scan.domains)}")
                st.markdown(f"**Started:** {created_at.strftime('%Y-%m-%d %H:%M:%S')}")
                if scan.duration_seconds:
                    st.markdown(f"**Duration:** {scan.duration_seconds:.1f} seconds")
            
            with col2:
                st.markdown("**Severity Breakdown:**")
                if scan.severity_breakdown:
                    for sev, count in scan.severity_breakdown.items():
                        if count > 0:
                            color = get_severity_color(sev)
                            st.markdown(f"<span style='color: {color};'>{sev.capitalize()}: {count}</span>", unsafe_allow_html=True)
                st.markdown(f"**Total Findings:** {scan.total_findings}")
            
            # Delete button
            if st.button("Delete Scan", key=f"delete_scan_{scan.id}", type="secondary"):
                if db.delete_scan(scan.id, user_id):
                    st.success("Scan deleted successfully")
                    db.log_audit(user_id, "SCAN_DELETED", f"Deleted scan #{scan.id}")
                    st.rerun()
                else:
                    st.error("Failed to delete scan")


# ============== PAGE: WEBHOOKS ==============

def render_webhooks_page():
    """Render webhooks configuration page."""
    st.markdown('<p class="main-header">Webhooks</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Configure notifications for scan completions</p>', unsafe_allow_html=True)
    
    st.divider()
    
    user_id = st.session_state.get('user_id')
    
    if not user_id:
        st.info("Login required to configure webhooks. Guest users cannot use this feature.")
        return
    
    # Add new webhook section
    st.markdown("### Add New Webhook")
    
    col1, col2 = st.columns(2)
    
    with col1:
        webhook_name = st.text_input("Webhook Name", placeholder="My Slack Webhook")
        webhook_url = st.text_input("Webhook URL", placeholder="https://hooks.slack.com/services/...")
    
    with col2:
        webhook_type = st.selectbox(
            "Webhook Type",
            ["generic", "slack", "discord", "teams"],
            format_func=lambda x: x.capitalize()
        )
        st.markdown("")
        st.markdown("")
    
    col_add, col_test = st.columns(2)
    
    with col_add:
        if st.button("Add Webhook", type="primary", use_container_width=True):
            if webhook_name and webhook_url:
                if webhook_url.startswith(('http://', 'https://')):
                    webhook_id = db.create_webhook(user_id, webhook_name, webhook_url, webhook_type)
                    if webhook_id:
                        st.success(f"Webhook '{webhook_name}' added successfully!")
                        db.log_audit(user_id, "WEBHOOK_CREATED", f"Created webhook: {webhook_name}")
                        st.rerun()
                    else:
                        st.error("Failed to create webhook")
                else:
                    st.error("Webhook URL must start with http:// or https://")
            else:
                st.warning("Please enter webhook name and URL")
    
    with col_test:
        if st.button("Test Webhook", use_container_width=True):
            if webhook_url:
                with st.spinner("Sending test notification..."):
                    success, error = notification_service.send_test_notification(webhook_url, webhook_type)
                    if success:
                        st.success("Test notification sent successfully!")
                    else:
                        st.error(f"Test failed: {error}")
            else:
                st.warning("Please enter a webhook URL to test")
    
    st.divider()
    
    # Existing webhooks
    st.markdown("### Your Webhooks")
    
    webhooks = db.get_user_webhooks(user_id)
    
    if not webhooks:
        st.info("No webhooks configured yet. Add one above to receive notifications.")
        return
    
    for webhook in webhooks:
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            st.markdown(f"**{webhook['name']}**")
            st.markdown(f"Type: {webhook['webhook_type'].capitalize()} | URL: {webhook['url'][:50]}...")
        
        with col2:
            if st.button("Test", key=f"test_wh_{webhook['id']}", use_container_width=True):
                success, error = notification_service.send_test_notification(
                    webhook['url'], 
                    webhook['webhook_type']
                )
                if success:
                    st.success("Test sent!")
                else:
                    st.error(f"Failed: {error}")
        
        with col3:
            if st.button("Delete", key=f"del_wh_{webhook['id']}", type="secondary", use_container_width=True):
                if db.delete_webhook(webhook['id'], user_id):
                    st.success("Webhook deleted")
                    db.log_audit(user_id, "WEBHOOK_DELETED", f"Deleted webhook: {webhook['name']}")
                    st.rerun()
                else:
                    st.error("Failed to delete")
        
        st.markdown("---")
    
    st.divider()
    
    # Info section
    st.markdown("### Webhook Information")
    st.markdown("""
    **Supported Webhook Types:**
    - **Generic**: Standard JSON payload sent to any endpoint
    - **Slack**: Formatted for Slack incoming webhooks
    - **Discord**: Formatted for Discord webhook embeds
    - **Teams**: Formatted for Microsoft Teams connectors
    
    **When notifications are sent:**
    - When a scan completes (success or failure)
    - When critical severity findings are detected
    """)


# ============== MAIN APPLICATION ==============

def main():
    """Main application entry point."""
    init_session_state()
    
    # Check authentication
    if not st.session_state.authenticated:
        render_login()
        return
    
    # Check session timeout
    if check_session_timeout():
        st.warning(format_error(ErrorCodes.AUTH_SESSION_EXPIRED))
        st.rerun()
    
    # Render sidebar and get settings
    enabled_modules, workers, output_formats = render_sidebar()
    
    # Route to appropriate page
    if st.session_state.current_page == "scan":
        render_scan_page(enabled_modules, workers, output_formats)
    elif st.session_state.current_page == "results":
        render_results_page()
    elif st.session_state.current_page == "history":
        render_history_page()
    elif st.session_state.current_page == "reports":
        render_reports_page()
    elif st.session_state.current_page == "email":
        render_email_page()
    elif st.session_state.current_page == "webhooks":
        render_webhooks_page()


if __name__ == "__main__":
    main()
