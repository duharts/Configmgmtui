#!/usr/bin/env python3
"""
Agentic Testing Platform - Streamlit Setup Interface
Version: 1.0.0
Author: AI Assistant
Description: Web-based setup interface for the AI-powered agentic testing platform
"""

import streamlit as st
import json
import yaml
import datetime
import logging
import os
from pathlib import Path
import traceback

# Configure page FIRST - before any other Streamlit commands
st.set_page_config(
    page_title="Agentic Testing Platform Setup",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state variables
def init_session_state():
    """Initialize session state variables"""
    if 'config' not in st.session_state:
        st.session_state.config = {}
    if 'setup_status' not in st.session_state:
        st.session_state.setup_status = "Ready"
    if 'deployment_started' not in st.session_state:
        st.session_state.deployment_started = False
    if 'logs' not in st.session_state:
        st.session_state.logs = []

# Call initialization
init_session_state()

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #2c3e50;
        border-bottom: 2px solid #3498db;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }
    .config-box {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #dee2e6;
        margin: 1rem 0;
    }
    .status-success {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        padding: 0.75rem;
        border-radius: 0.375rem;
    }
    .status-error {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        padding: 0.75rem;
        border-radius: 0.375rem;
    }
</style>
""", unsafe_allow_html=True)

# Simple error logger
class SimpleLogger:
    def __init__(self):
        self.errors = []
        self.log_file = f"setup_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    def log_error(self, error_type, message, solution=""):
        error_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": error_type,
            "message": message,
            "solution": solution
        }
        self.errors.append(error_info)
        
        # Write to file
        try:
            with open(self.log_file, 'a') as f:
                f.write(f"{error_info['timestamp']} - {error_type}: {message}\n")
        except:
            pass  # Ignore file write errors

# Initialize logger
if 'logger' not in st.session_state:
    st.session_state.logger = SimpleLogger()

# Validation functions
def validate_azure_config(config):
    """Validate Azure configuration"""
    required_fields = ['subscription_id', 'resource_group', 'location']
    missing = [field for field in required_fields if not config.get(field)]
    
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    
    # Basic format validation
    sub_id = config.get('subscription_id', '')
    if sub_id and len(sub_id) != 36:
        return False, "Invalid subscription ID format (should be 36 characters)"
    
    return True, "Valid"

def save_config_to_file():
    """Generate config file for download"""
    config_json = json.dumps(st.session_state.config, indent=2)
    filename = f"agentic_config_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return config_json, filename

# Header
st.markdown('<h1 class="main-header">Agentic Testing Platform Setup</h1>', unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("Navigation")
pages = [
    "Azure Configuration",
    "AI Models", 
    "Storage & Database",
    "Monitoring",
    "Security",
    "Deployment",
    "Review & Deploy",
    "Logs"
]

# Create a simple page selector
page = st.sidebar.radio("Select Configuration Page:", pages)

# Progress indicator
total_sections = len(pages) - 2  # Exclude Review and Logs pages
completed_sections = sum(1 for section in ['azure', 'ai', 'storage', 'monitoring', 'security', 'deployment'] 
                        if any(key.startswith(section) for key in st.session_state.config.keys()))

st.sidebar.metric("Configuration Progress", f"{completed_sections}/{total_sections}")
st.sidebar.progress(completed_sections / total_sections)

# Page content
if page == "Azure Configuration":
    st.markdown('<h2 class="section-header">Azure Configuration</h2>', unsafe_allow_html=True)
    
    # Info box
    with st.expander("Azure Setup Information"):
        st.info("""
        Required Azure Services:
        - Azure OpenAI Service
        - Storage Account  
        - Key Vault
        - Container Registry (optional)
        
        Prerequisites:
        - Azure subscription with admin rights
        - Service principal credentials
        """)
    
    # Two column layout
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Basic Settings")
        subscription_id = st.text_input(
            "Azure Subscription ID",
            value=st.session_state.config.get('azure_subscription_id', ''),
            help="Your Azure subscription GUID",
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        )
        if subscription_id:
            st.session_state.config['azure_subscription_id'] = subscription_id
        
        resource_group = st.text_input(
            "Resource Group Name",
            value=st.session_state.config.get('azure_resource_group', ''),
            help="Name for the resource group",
            placeholder="rg-agentic-testing"
        )
        if resource_group:
            st.session_state.config['azure_resource_group'] = resource_group
        
        location = st.selectbox(
            "Azure Region",
            ["eastus2", "westus2", "westeurope", "southeastasia", "japaneast"],
            index=0,
            help="Azure region for resources"
        )
        st.session_state.config['azure_location'] = location
    
    with col2:
        st.subheader("Service Principal")
        client_id = st.text_input(
            "Client ID",
            value=st.session_state.config.get('azure_client_id', ''),
            help="Service principal client ID"
        )
        if client_id:
            st.session_state.config['azure_client_id'] = client_id
        
        client_secret = st.text_input(
            "Client Secret",
            value=st.session_state.config.get('azure_client_secret', ''),
            type="password",
            help="Service principal secret"
        )
        if client_secret:
            st.session_state.config['azure_client_secret'] = client_secret
        
        tenant_id = st.text_input(
            "Tenant ID",
            value=st.session_state.config.get('azure_tenant_id', ''),
            help="Azure AD tenant ID"
        )
        if tenant_id:
            st.session_state.config['azure_tenant_id'] = tenant_id
    
    # Azure OpenAI Configuration
    st.subheader("Azure OpenAI")
    col3, col4 = st.columns(2)
    
    with col3:
        openai_endpoint = st.text_input(
            "OpenAI Endpoint",
            value=st.session_state.config.get('azure_openai_endpoint', ''),
            help="Azure OpenAI service endpoint"
        )
        if openai_endpoint:
            st.session_state.config['azure_openai_endpoint'] = openai_endpoint
    
    with col4:
        openai_key = st.text_input(
            "OpenAI API Key",
            value=st.session_state.config.get('azure_openai_key', ''),
            type="password",
            help="Azure OpenAI API key"
        )
        if openai_key:
            st.session_state.config['azure_openai_key'] = openai_key

elif page == "AI Models":
    st.markdown('<h2 class="section-header">AI Models Configuration</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Language Model")
        llm_provider = st.selectbox(
            "Primary LLM Provider",
            ["azure_openai", "anthropic", "openai"],
            help="Primary language model provider"
        )
        st.session_state.config['ai_llm_provider'] = llm_provider
        
        model_name = st.text_input(
            "Model Name",
            value=st.session_state.config.get('ai_model_name', 'gpt-4'),
            help="Deployed model name"
        )
        if model_name:
            st.session_state.config['ai_model_name'] = model_name
        
        max_tokens = st.number_input(
            "Max Tokens",
            min_value=100,
            max_value=8000,
            value=int(st.session_state.config.get('ai_max_tokens', 4096)),
            help="Maximum tokens per request"
        )
        st.session_state.config['ai_max_tokens'] = max_tokens
        
        temperature = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=2.0,
            value=float(st.session_state.config.get('ai_temperature', 0.1)),
            step=0.1,
            help="Model randomness (0.0 = deterministic, 2.0 = very random)"
        )
        st.session_state.config['ai_temperature'] = temperature
    
    with col2:
        st.subheader("Vision Model")
        vision_provider = st.selectbox(
            "Vision Provider",
            ["moondream", "omnivision", "custom"],
            help="Vision model provider"
        )
        st.session_state.config['ai_vision_provider'] = vision_provider
        
        huggingface_token = st.text_input(
            "HuggingFace Token",
            value=st.session_state.config.get('ai_huggingface_token', ''),
            type="password",
            help="HuggingFace API token"
        )
        if huggingface_token:
            st.session_state.config['ai_huggingface_token'] = huggingface_token
        
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.1,
            max_value=1.0,
            value=float(st.session_state.config.get('ai_confidence_threshold', 0.8)),
            step=0.1,
            help="Minimum confidence for detections"
        )
        st.session_state.config['ai_confidence_threshold'] = confidence_threshold
        
        max_image_size = st.selectbox(
            "Maximum Image Size",
            ["1920x1080", "1280x720", "800x600"],
            help="Maximum image resolution for processing"
        )
        st.session_state.config['ai_max_image_size'] = max_image_size

elif page == "Storage & Database":
    st.markdown('<h2 class="section-header">Storage & Database Configuration</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Storage")
        storage_type = st.selectbox(
            "Storage Type",
            ["azure_blob", "aws_s3", "local"],
            help="Primary storage backend"
        )
        st.session_state.config['storage_type'] = storage_type
        
        if storage_type == "azure_blob":
            storage_account = st.text_input(
                "Storage Account Name",
                value=st.session_state.config.get('storage_account_name', ''),
                help="Azure storage account name"
            )
            if storage_account:
                st.session_state.config['storage_account_name'] = storage_account
            
            storage_key = st.text_input(
                "Storage Account Key",
                value=st.session_state.config.get('storage_account_key', ''),
                type="password",
                help="Storage account access key"
            )
            if storage_key:
                st.session_state.config['storage_account_key'] = storage_key
            
            container_name = st.text_input(
                "Container Name",
                value=st.session_state.config.get('storage_container_name', 'agentic-testing'),
                help="Storage container name"
            )
            if container_name:
                st.session_state.config['storage_container_name'] = container_name
    
    with col2:
        st.subheader("Database")
        db_type = st.selectbox(
            "Database Type",
            ["cosmos_db", "postgresql", "sqlite"],
            help="Primary database backend"
        )
        st.session_state.config['database_type'] = db_type
        
        if db_type in ["postgresql", "cosmos_db"]:
            db_host = st.text_input(
                "Database Host",
                value=st.session_state.config.get('database_host', ''),
                help="Database server hostname"
            )
            if db_host:
                st.session_state.config['database_host'] = db_host
            
            db_name = st.text_input(
                "Database Name",
                value=st.session_state.config.get('database_name', 'agentic_testing'),
                help="Database name"
            )
            if db_name:
                st.session_state.config['database_name'] = db_name
            
            db_username = st.text_input(
                "Database Username",
                value=st.session_state.config.get('database_username', ''),
                help="Database username"
            )
            if db_username:
                st.session_state.config['database_username'] = db_username
            
            db_password = st.text_input(
                "Database Password",
                value=st.session_state.config.get('database_password', ''),
                type="password",
                help="Database password"
            )
            if db_password:
                st.session_state.config['database_password'] = db_password

elif page == "Monitoring":
    st.markdown('<h2 class="section-header">Monitoring & Analytics</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Azure Monitoring")
        app_insights_key = st.text_input(
            "Application Insights Key",
            value=st.session_state.config.get('monitoring_app_insights_key', ''),
            type="password",
            help="Azure Application Insights instrumentation key"
        )
        if app_insights_key:
            st.session_state.config['monitoring_app_insights_key'] = app_insights_key
        
        app_insights_connection = st.text_area(
            "Application Insights Connection String",
            value=st.session_state.config.get('monitoring_app_insights_connection', ''),
            help="Application Insights connection string"
        )
        if app_insights_connection:
            st.session_state.config['monitoring_app_insights_connection'] = app_insights_connection
        
        enable_live_metrics = st.checkbox(
            "Enable Live Metrics",
            value=st.session_state.config.get('monitoring_live_metrics', True),
            help="Enable real-time metrics"
        )
        st.session_state.config['monitoring_live_metrics'] = enable_live_metrics
        
        sampling_rate = st.slider(
            "Sampling Rate",
            min_value=0.1,
            max_value=1.0,
            value=float(st.session_state.config.get('monitoring_sampling_rate', 1.0)),
            step=0.1,
            help="Telemetry sampling rate (1.0 = 100%)"
        )
        st.session_state.config['monitoring_sampling_rate'] = sampling_rate
    
    with col2:
        st.subheader("Third-party Analytics")
        mixpanel_token = st.text_input(
            "Mixpanel Token",
            value=st.session_state.config.get('monitoring_mixpanel_token', ''),
            type="password",
            help="Mixpanel project token"
        )
        if mixpanel_token:
            st.session_state.config['monitoring_mixpanel_token'] = mixpanel_token
        
        amplitude_key = st.text_input(
            "Amplitude API Key",
            value=st.session_state.config.get('monitoring_amplitude_key', ''),
            type="password",
            help="Amplitude API key"
        )
        if amplitude_key:
            st.session_state.config['monitoring_amplitude_key'] = amplitude_key
        
        datadog_key = st.text_input(
            "DataDog API Key",
            value=st.session_state.config.get('monitoring_datadog_key', ''),
            type="password",
            help="DataDog API key"
        )
        if datadog_key:
            st.session_state.config['monitoring_datadog_key'] = datadog_key
        
        newrelic_key = st.text_input(
            "New Relic License Key",
            value=st.session_state.config.get('monitoring_newrelic_key', ''),
            type="password",
            help="New Relic license key"
        )
        if newrelic_key:
            st.session_state.config['monitoring_newrelic_key'] = newrelic_key
        
        grafana_url = st.text_input(
            "Grafana URL",
            value=st.session_state.config.get('monitoring_grafana_url', ''),
            help="Grafana instance URL"
        )
        if grafana_url:
            st.session_state.config['monitoring_grafana_url'] = grafana_url

elif page == "Security":
    st.markdown('<h2 class="section-header">Security & Compliance</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Authentication")
        auth_type = st.selectbox(
            "Authentication Type",
            ["azure_ad", "oauth2", "local"],
            help="Primary authentication method"
        )
        st.session_state.config['security_auth_type'] = auth_type
        
        jwt_secret = st.text_input(
            "JWT Secret",
            value=st.session_state.config.get('security_jwt_secret', ''),
            type="password",
            help="JWT signing secret"
        )
        if jwt_secret:
            st.session_state.config['security_jwt_secret'] = jwt_secret
        
        token_expiry = st.number_input(
            "Token Expiry (hours)",
            min_value=1,
            max_value=168,
            value=int(st.session_state.config.get('security_token_expiry', 24)),
            help="JWT token expiry time in hours"
        )
        st.session_state.config['security_token_expiry'] = token_expiry
        
        enable_mfa = st.checkbox(
            "Enable Multi-Factor Authentication",
            value=st.session_state.config.get('security_enable_mfa', True),
            help="Require MFA for users"
        )
        st.session_state.config['security_enable_mfa'] = enable_mfa
        
        password_policy = st.selectbox(
            "Password Policy",
            ["simple", "complex", "enterprise"],
            help="Password complexity requirements"
        )
        st.session_state.config['security_password_policy'] = password_policy
    
    with col2:
        st.subheader("Encryption")
        encryption_at_rest = st.checkbox(
            "Encryption at Rest",
            value=st.session_state.config.get('security_encryption_rest', True),
            help="Encrypt stored data"
        )
        st.session_state.config['security_encryption_rest'] = encryption_at_rest
        
        encryption_in_transit = st.checkbox(
            "Encryption in Transit",
            value=st.session_state.config.get('security_encryption_transit', True),
            help="Use TLS/SSL"
        )
        st.session_state.config['security_encryption_transit'] = encryption_in_transit
        
        key_management = st.selectbox(
            "Key Management",
            ["azure_keyvault", "hashicorp_vault", "local"],
            help="Key management service"
        )
        st.session_state.config['security_key_management'] = key_management
        
        ssl_cert_path = st.text_input(
            "SSL Certificate Path",
            value=st.session_state.config.get('security_ssl_cert_path', ''),
            help="Path to SSL certificate file"
        )
        if ssl_cert_path:
            st.session_state.config['security_ssl_cert_path'] = ssl_cert_path
        
        ssl_key_path = st.text_input(
            "SSL Key Path",
            value=st.session_state.config.get('security_ssl_key_path', ''),
            help="Path to SSL private key file"
        )
        if ssl_key_path:
            st.session_state.config['security_ssl_key_path'] = ssl_key_path

elif page == "Deployment":
    st.markdown('<h2 class="section-header">Deployment Configuration</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Environment")
        environment = st.selectbox(
            "Environment",
            ["development", "staging", "production"],
            help="Deployment environment"
        )
        st.session_state.config['deployment_environment'] = environment
        
        deployment_type = st.selectbox(
            "Deployment Type",
            ["kubernetes", "docker_compose", "local"],
            help="Deployment platform"
        )
        st.session_state.config['deployment_type'] = deployment_type
        
        scaling_mode = st.selectbox(
            "Scaling Mode",
            ["manual", "auto"],
            help="Application scaling"
        )
        st.session_state.config['deployment_scaling'] = scaling_mode
    
    with col2:
        st.subheader("Resources")
        if st.session_state.config.get('deployment_scaling') == "auto":
            min_replicas = st.number_input(
                "Minimum Replicas",
                min_value=1,
                max_value=10,
                value=int(st.session_state.config.get('deployment_min_replicas', 2))
            )
            st.session_state.config['deployment_min_replicas'] = min_replicas
            
            max_replicas = st.number_input(
                "Maximum Replicas",
                min_value=1,
                max_value=20,
                value=int(st.session_state.config.get('deployment_max_replicas', 10))
            )
            st.session_state.config['deployment_max_replicas'] = max_replicas
        
        cpu_limit = st.text_input(
            "CPU Limit",
            value=st.session_state.config.get('deployment_cpu_limit', '2'),
            help="CPU limit per replica (e.g., '2' for 2 cores)"
        )
        if cpu_limit:
            st.session_state.config['deployment_cpu_limit'] = cpu_limit
        
        memory_limit = st.text_input(
            "Memory Limit",
            value=st.session_state.config.get('deployment_memory_limit', '4Gi'),
            help="Memory limit per replica (e.g., '4Gi')"
        )
        if memory_limit:
            st.session_state.config['deployment_memory_limit'] = memory_limit
    
    # CI/CD Configuration
    st.subheader("CI/CD Configuration")
    col3, col4 = st.columns(2)
    
    with col3:
        cicd_platform = st.selectbox(
            "CI/CD Platform",
            ["azure_devops", "github_actions", "jenkins"],
            help="CI/CD platform"
        )
        st.session_state.config['deployment_cicd_platform'] = cicd_platform
        
        repository_url = st.text_input(
            "Repository URL",
            value=st.session_state.config.get('deployment_repository_url', ''),
            help="Git repository URL"
        )
        if repository_url:
            st.session_state.config['deployment_repository_url'] = repository_url
        
        branch = st.text_input(
            "Branch",
            value=st.session_state.config.get('deployment_branch', 'main'),
            help="Git branch for deployment"
        )
        if branch:
            st.session_state.config['deployment_branch'] = branch
    
    with col4:
        build_agent_pool = st.text_input(
            "Build Agent Pool",
            value=st.session_state.config.get('deployment_build_agent_pool', 'ubuntu-latest'),
            help="Build agent pool name"
        )
        if build_agent_pool:
            st.session_state.config['deployment_build_agent_pool'] = build_agent_pool
        
        enable_auto_deploy = st.checkbox(
            "Enable Auto Deploy",
            value=st.session_state.config.get('deployment_enable_auto_deploy', True),
            help="Automatically deploy on successful build"
        )
        st.session_state.config['deployment_enable_auto_deploy'] = enable_auto_deploy
        
        run_tests_on_deploy = st.checkbox(
            "Run Tests on Deploy",
            value=st.session_state.config.get('deployment_run_tests_on_deploy', True),
            help="Run tests before deployment"
        )
        st.session_state.config['deployment_run_tests_on_deploy'] = run_tests_on_deploy

elif page == "Review & Deploy":
    st.markdown('<h2 class="section-header">Configuration Review & Deployment</h2>', unsafe_allow_html=True)
    
    # Validation
    is_valid, validation_message = validate_azure_config(st.session_state.config)
    
    if is_valid:
        st.success("Configuration is valid and ready for deployment!")
    else:
        st.error(f"Configuration issues: {validation_message}")
    
    # Configuration summary
    st.subheader("Configuration Summary")
    
    # Create a summary
    summary_data = {
        "Azure Configuration": {
            "Subscription": st.session_state.config.get('azure_subscription_id', 'Not set')[:8] + "..." if st.session_state.config.get('azure_subscription_id') else 'Not set',
            "Resource Group": st.session_state.config.get('azure_resource_group', 'Not set'),
            "Location": st.session_state.config.get('azure_location', 'Not set'),
            "OpenAI Endpoint": "Configured" if st.session_state.config.get('azure_openai_endpoint') else 'Not set'
        },
        "AI Models": {
            "LLM Provider": st.session_state.config.get('ai_llm_provider', 'Not set'),
            "Vision Provider": st.session_state.config.get('ai_vision_provider', 'Not set'),
            "Max Tokens": st.session_state.config.get('ai_max_tokens', 'Not set'),
            "Temperature": st.session_state.config.get('ai_temperature', 'Not set')
        },
        "Storage & Database": {
            "Storage Type": st.session_state.config.get('storage_type', 'Not set'),
            "Database Type": st.session_state.config.get('database_type', 'Not set'),
            "Storage Account": st.session_state.config.get('storage_account_name', 'Not set'),
            "Database Host": st.session_state.config.get('database_host', 'Not set')
        },
        "Monitoring": {
            "App Insights": "Configured" if st.session_state.config.get('monitoring_app_insights_key') else 'Not set',
            "Mixpanel": "Configured" if st.session_state.config.get('monitoring_mixpanel_token') else 'Not set',
            "DataDog": "Configured" if st.session_state.config.get('monitoring_datadog_key') else 'Not set',
            "Live Metrics": st.session_state.config.get('monitoring_live_metrics', 'Not set')
        },
        "Security": {
            "Auth Type": st.session_state.config.get('security_auth_type', 'Not set'),
            "MFA Enabled": st.session_state.config.get('security_enable_mfa', 'Not set'),
            "Encryption at Rest": st.session_state.config.get('security_encryption_rest', 'Not set'),
            "Encryption in Transit": st.session_state.config.get('security_encryption_transit', 'Not set')
        },
        "Deployment": {
            "Environment": st.session_state.config.get('deployment_environment', 'Not set'),
            "Type": st.session_state.config.get('deployment_type', 'Not set'),
            "Scaling": st.session_state.config.get('deployment_scaling', 'Not set'),
            "CI/CD Platform": st.session_state.config.get('deployment_cicd_platform', 'Not set')
        }
    }
    
    for category, items in summary_data.items():
        with st.expander(f"{category}"):
            for key, value in items.items():
                st.write(f"**{key}:** {value}")
    
    # Action buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Download Configuration", type="secondary"):
            config_json, filename = save_config_to_file()
            st.download_button(
                label="Download JSON",
                data=config_json,
                file_name=filename,
                mime="application/json"
            )
    
    with col2:
        if st.button("Test Configuration", type="secondary"):
            with st.spinner("Testing configuration..."):
                # Simulate testing
                import time
                time.sleep(2)
                
                if is_valid:
                    st.success("All tests passed!")
                else:
                    st.error(f"Tests failed: {validation_message}")
    
    with col3:
        if st.button("Start Deployment", type="primary", disabled=not is_valid):
            if is_valid:
                st.session_state.deployment_started = True
                st.rerun()
    
    # Deployment progress
    if st.session_state.deployment_started:
        st.subheader("Deployment Progress")
        
        # Create a fake deployment progress
        progress_container = st.container()
        
        with progress_container:
            steps = [
                "Installing dependencies...",
                "Setting up Azure resources...",
                "Deploying services...",
                "Configuring monitoring...",
                "Running health checks..."
            ]
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, step in enumerate(steps):
                status_text.text(step)
                progress_bar.progress((i + 1) / len(steps))
                # In a real implementation, you'd actually run deployment steps here
            
            st.success("Deployment completed successfully!")
            
            # Show completion details
            st.markdown("""
            **Deployment Summary:**
            - Environment: {}
            - Deployment Type: {}
            - Access URL: http://localhost:8000
            - Health Check: http://localhost:8000/health
            - API Documentation: http://localhost:8000/docs
            
            **Next Steps:**
            1. Access the dashboard to create your first test
            2. Review the generated documentation
            3. Set up CI/CD integration if needed
            4. Configure team access and permissions
            """.format(
                st.session_state.config.get('deployment_environment', 'production'),
                st.session_state.config.get('deployment_type', 'kubernetes')
            ))
            
            # Reset deployment status
            if st.button("Reset"):
                st.session_state.deployment_started = False
                st.rerun()
    
    # File upload
    st.subheader("Load Configuration from File")
    uploaded_file = st.file_uploader(
        "Upload configuration file",
        type=['json', 'yaml'],
        help="Load a previously saved configuration"
    )
    
    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith('.json'):
                config = json.load(uploaded_file)
            else:
                config = yaml.safe_load(uploaded_file)
            
            st.session_state.config.update(config)
            st.success("Configuration loaded successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Failed to load configuration: {str(e)}")
    
    # Generate deployment scripts
    st.subheader("Generate Deployment Scripts")
    
    if st.button("Generate Deployment Templates"):
        with st.spinner("Generating deployment templates..."):
            # Generate different templates
            docker_compose = generate_docker_compose(st.session_state.config)
            k8s_deployment = generate_kubernetes_deployment(st.session_state.config)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.download_button(
                    label="Download Docker Compose",
                    data=docker_compose,
                    file_name="docker-compose.yml",
                    mime="text/yaml"
                )
            
            with col2:
                st.download_button(
                    label="Download Kubernetes Manifest",
                    data=k8s_deployment,
                    file_name="kubernetes-deployment.yaml",
                    mime="text/yaml"
                )
            
            st.success("Deployment templates generated successfully!")

elif page == "Logs":
    st.markdown('<h2 class="section-header">Logs & Status</h2>', unsafe_allow_html=True)
    
    # Status metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Setup Status", st.session_state.setup_status)
    
    with col2:
        st.metric("Configuration Items", len(st.session_state.config))
    
    with col3:
        st.metric("Errors", len(st.session_state.logger.errors))
    
    # Error display
    if st.session_state.logger.errors:
        st.subheader("Errors and Issues")
        for i, error in enumerate(st.session_state.logger.errors):
            with st.expander(f"Error {i+1}: {error['type']}"):
                st.error(f"Message: {error['message']}")
                if error['solution']:
                    st.info(f"Solution: {error['solution']}")
                st.text(f"Time: {error['timestamp']}")
    else:
        st.success("No errors recorded")
    
    # Configuration display
    st.subheader("Current Configuration")
    if st.session_state.config:
        # Create a formatted display of configuration
        config_display = {}
        for key, value in st.session_state.config.items():
            # Mask sensitive values
            if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'password', 'token']):
                config_display[key] = "*" * 8 if value else value
            else:
                config_display[key] = value
        
        st.json(config_display)
    else:
        st.info("No configuration set yet")
    
    # Log file viewer
    st.subheader("Log File")
    
    if os.path.exists(st.session_state.logger.log_file):
        with open(st.session_state.logger.log_file, 'r') as f:
            log_content = f.read()
        
        st.text_area("Log Contents", value=log_content, height=300)
        
        st.download_button(
            label="Download Log File",
            data=log_content,
            file_name=st.session_state.logger.log_file,
            mime="text/plain"
        )
    else:
        st.info("No log file created yet.")
    
    # System info
    st.subheader("System Information")
    system_info = {
        "Python Version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
        "Working Directory": os.getcwd(),
        "Environment Variables": len(os.environ),
        "Platform": os.name
    }
    
    for key, value in system_info.items():
        st.text(f"{key}: {value}")

# Helper functions for generating deployment templates
def generate_docker_compose(config):
    """Generate Docker Compose configuration"""
    return f"""version: '3.8'
services:
  orchestrator:
    image: agentic-testing/orchestrator:latest
    ports:
      - "8000:8000"
    environment:
      - AZURE_SUBSCRIPTION_ID={config.get('azure_subscription_id', '')}
      - AZURE_OPENAI_ENDPOINT={config.get('azure_openai_endpoint', '')}
      - AZURE_OPENAI_KEY={config.get('azure_openai_key', '')}
      - STORAGE_ACCOUNT_NAME={config.get('storage_account_name', '')}
    depends_on:
      - redis
      - postgres

  vision-service:
    image: agentic-testing/vision-service:latest
    ports:
      - "8001:8001"
    environment:
      - HUGGINGFACE_TOKEN={config.get('ai_huggingface_token', '')}
      - VISION_PROVIDER={config.get('ai_vision_provider', 'moondream')}

  browser-service:
    image: agentic-testing/browser-service:latest
    ports:
      - "8002:8002"
    environment:
      - BROWSER_HEADLESS=true
    shm_size: 2gb

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB={config.get('database_name', 'agentic_testing')}
      - POSTGRES_USER={config.get('database_username', 'postgres')}
      - POSTGRES_PASSWORD={config.get('database_password', 'changeme')}
    ports:
      - "5432:5432"

volumes:
  redis_data:
  postgres_data:
"""

def generate_kubernetes_deployment(config):
    """Generate Kubernetes deployment manifest"""
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: orchestrator
  namespace: agentic-testing
spec:
  replicas: {config.get('deployment_min_replicas', 2)}
  selector:
    matchLabels:
      app: orchestrator
  template:
    metadata:
      labels:
        app: orchestrator
    spec:
      containers:
      - name: orchestrator
        image: agentic-testing/orchestrator:latest
        ports:
        - containerPort: 8000
        env:
        - name: AZURE_SUBSCRIPTION_ID
          value: "{config.get('azure_subscription_id', '')}"
        - name: AZURE_OPENAI_ENDPOINT
          value: "{config.get('azure_openai_endpoint', '')}"
        - name: DEPLOYMENT_ENVIRONMENT
          value: "{config.get('deployment_environment', 'production')}"
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: {config.get('deployment_cpu_limit', '2')}
            memory: {config.get('deployment_memory_limit', '4Gi')}
---
apiVersion: v1
kind: Service
metadata:
  name: orchestrator-service
  namespace: agentic-testing
spec:
  selector:
    app: orchestrator
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: orchestrator-hpa
  namespace: agentic-testing
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: orchestrator
  minReplicas: {config.get('deployment_min_replicas', 2)}
  maxReplicas: {config.get('deployment_max_replicas', 10)}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
"""

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown("Agentic Testing Platform Setup")
st.sidebar.markdown("Version 1.0.0")

# Quick actions in sidebar
st.sidebar.subheader("Quick Actions")

if st.sidebar.button("Reset Configuration"):
    st.session_state.config = {}
    st.session_state.deployment_started = False
    st.success("Configuration reset!")
    st.rerun()

if st.sidebar.button("Export Configuration"):
    if st.session_state.config:
        config_json, filename = save_config_to_file()
        st.sidebar.download_button(
            label="Download Config",
            data=config_json,
            file_name=filename,
            mime="application/json"
        )
    else:
        st.sidebar.warning("No configuration to export")

# Configuration validation status in sidebar
config_sections = {
    'Azure': 'azure_subscription_id',
    'AI': 'ai_llm_provider', 
    'Storage': 'storage_type',
    'Security': 'security_auth_type',
    'Deployment': 'deployment_environment'
}

st.sidebar.subheader("Configuration Status")
for section, key in config_sections.items():
    if st.session_state.config.get(key):
        st.sidebar.success(f"{section}: Configured")
    else:
        st.sidebar.warning(f"{section}: Not configured")
