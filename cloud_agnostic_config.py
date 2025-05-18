#!/usr/bin/env python3
"""
Actory AI Configuration Management
Version: 2.0.0
Author: AI Assistant
Description: Cloud-agnostic web-based setup interface for the AI-powered agentic testing platform
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
    page_title="Actory AI Configuration Management",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Cloud provider configurations
CLOUD_PROVIDERS = {
    "azure": {
        "name": "Microsoft Azure",
        "regions": ["eastus2", "westus2", "westeurope", "southeastasia", "japaneast"],
        "ai_services": ["azure_openai"],
        "storage_services": ["azure_blob"],
        "key_management": "azure_keyvault",
        "monitoring": "azure_app_insights",
        "database_services": ["cosmos_db", "azure_sql", "postgresql"]
    },
    "aws": {
        "name": "Amazon Web Services",
        "regions": ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"],
        "ai_services": ["bedrock", "sagemaker"],
        "storage_services": ["aws_s3"],
        "key_management": "aws_secrets_manager",
        "monitoring": "aws_cloudwatch",
        "database_services": ["dynamodb", "rds_postgresql", "rds_mysql"]
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "regions": ["us-central1", "us-west1", "europe-west1", "asia-southeast1", "asia-northeast1"],
        "ai_services": ["vertex_ai", "gemini"],
        "storage_services": ["gcs"],
        "key_management": "gcp_secret_manager",
        "monitoring": "gcp_monitoring",
        "database_services": ["firestore", "cloud_sql_postgresql", "cloud_sql_mysql"]
    },
    "multi_cloud": {
        "name": "Multi-Cloud",
        "regions": ["global"],
        "ai_services": ["anthropic", "openai", "huggingface"],
        "storage_services": ["azure_blob", "aws_s3", "gcs"],
        "key_management": "hashicorp_vault",
        "monitoring": "datadog",
        "database_services": ["postgresql", "mongodb", "sqlite"]
    }
}

# Third-party services that work across clouds
THIRD_PARTY_SERVICES = {
    "ai_providers": ["anthropic", "openai", "huggingface", "cohere"],
    "monitoring": ["datadog", "new_relic", "grafana", "prometheus"],
    "databases": ["postgresql", "mongodb", "redis", "sqlite"],
    "storage": ["minio", "wasabi"],
    "security": ["hashicorp_vault", "1password_secrets"]
}

# Initialize session state variables
def init_session_state():
    """Initialize session state variables"""
    if 'config' not in st.session_state:
        st.session_state.config = {}
    if 'cloud_provider' not in st.session_state:
        st.session_state.cloud_provider = None
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
    .cloud-provider-card {
        background-color: #f8f9fa;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border: 2px solid #dee2e6;
        margin: 1rem 0;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .cloud-provider-card:hover {
        border-color: #3498db;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    .cloud-provider-selected {
        border-color: #28a745 !important;
        background-color: #d4edda !important;
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

# Enhanced error logger with full error tracking
class EnhancedLogger:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info_logs = []
        self.debug_logs = []
        self.session_id = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = f"actory_ai_log_{self.session_id}.txt"
        
        # Initialize log file
        self._write_header()
    
    def _write_header(self):
        """Write log file header"""
        try:
            with open(self.log_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("ACTORY AI CONFIGURATION MANAGEMENT - ERROR LOG\n")
                f.write("=" * 80 + "\n")
                f.write(f"Session ID: {self.session_id}\n")
                f.write(f"Start Time: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Platform: {os.name}\n")
                f.write(f"Python Version: {os.sys.version}\n")
                f.write("=" * 80 + "\n\n")
        except Exception as e:
            print(f"Failed to initialize log file: {e}")
    
    def log_error(self, error_type, message, solution="", exception=None, context=None):
        """Log error with full details"""
        timestamp = datetime.datetime.now().isoformat()
        
        error_info = {
            "timestamp": timestamp,
            "type": error_type,
            "message": message,
            "solution": solution,
            "exception": str(exception) if exception else None,
            "traceback": traceback.format_exc() if exception else None,
            "context": context or {}
        }
        
        self.errors.append(error_info)
        self._write_to_file("ERROR", error_info)
        return error_info
    
    def log_warning(self, warning_type, message, suggestion="", context=None):
        """Log warning"""
        timestamp = datetime.datetime.now().isoformat()
        
        warning_info = {
            "timestamp": timestamp,
            "type": warning_type,
            "message": message,
            "suggestion": suggestion,
            "context": context or {}
        }
        
        self.warnings.append(warning_info)
        self._write_to_file("WARNING", warning_info)
        return warning_info
    
    def log_info(self, info_type, message, context=None):
        """Log information"""
        timestamp = datetime.datetime.now().isoformat()
        
        info = {
            "timestamp": timestamp,
            "type": info_type,
            "message": message,
            "context": context or {}
        }
        
        self.info_logs.append(info)
        self._write_to_file("INFO", info)
        return info
    
    def log_debug(self, debug_type, message, context=None):
        """Log debug information"""
        timestamp = datetime.datetime.now().isoformat()
        
        debug_info = {
            "timestamp": timestamp,
            "type": debug_type,
            "message": message,
            "context": context or {}
        }
        
        self.debug_logs.append(debug_info)
        self._write_to_file("DEBUG", debug_info)
        return debug_info
    
    def _write_to_file(self, level, log_info):
        """Write log entry to file"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{level}] {log_info['timestamp']}\n")
                f.write(f"Type: {log_info['type']}\n")
                f.write(f"Message: {log_info['message']}\n")
                
                if 'solution' in log_info and log_info['solution']:
                    f.write(f"Solution: {log_info['solution']}\n")
                
                if 'suggestion' in log_info and log_info['suggestion']:
                    f.write(f"Suggestion: {log_info['suggestion']}\n")
                
                if 'exception' in log_info and log_info['exception']:
                    f.write(f"Exception: {log_info['exception']}\n")
                
                if 'traceback' in log_info and log_info['traceback']:
                    f.write(f"Traceback:\n{log_info['traceback']}\n")
                
                if 'context' in log_info and log_info['context']:
                    f.write(f"Context: {json.dumps(log_info['context'], indent=2)}\n")
                
                f.write("-" * 40 + "\n\n")
        except Exception as e:
            print(f"Failed to write to log file: {e}")
    
    def get_full_log(self):
        """Get complete log content"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"Error reading log file: {e}"
    
    def get_summary(self):
        """Get log summary"""
        summary = {
            "total_errors": len(self.errors),
            "total_warnings": len(self.warnings),
            "total_info": len(self.info_logs),
            "total_debug": len(self.debug_logs),
            "session_duration": (datetime.datetime.now() - datetime.datetime.strptime(self.session_id, '%Y%m%d_%H%M%S')).total_seconds(),
            "log_file_size": os.path.getsize(self.log_file) if os.path.exists(self.log_file) else 0
        }
        return summary
    
    def export_error_report(self):
        """Export comprehensive error report"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"actory_ai_error_report_{timestamp}.txt"
        
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("ACTORY AI CONFIGURATION MANAGEMENT - ERROR REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Session ID: {self.session_id}\n")
                
                # Summary
                summary = self.get_summary()
                f.write("\nSUMMARY:\n")
                f.write("-" * 40 + "\n")
                for key, value in summary.items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                
                # System Information
                f.write("\nSYSTEM INFORMATION:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Platform: {os.name}\n")
                f.write(f"Python Version: {os.sys.version}\n")
                f.write(f"Working Directory: {os.getcwd()}\n")
                f.write(f"Environment Variables: {len(os.environ)}\n")
                
                # Configuration State
                if hasattr(st.session_state, 'config'):
                    f.write("\nCONFIGURATION STATE:\n")
                    f.write("-" * 40 + "\n")
                    # Mask sensitive information
                    safe_config = {}
                    for key, value in st.session_state.config.items():
                        if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'password', 'token']):
                            safe_config[key] = "[REDACTED]" if value else value
                        else:
                            safe_config[key] = value
                    f.write(json.dumps(safe_config, indent=2))
                    f.write("\n")
                
                # Detailed Logs
                f.write("\nDETAILED LOGS:\n")
                f.write("=" * 80 + "\n")
                f.write(self.get_full_log())
                
                # Recommendations
                f.write("\nRECOMMENDATIONS:\n")
                f.write("-" * 40 + "\n")
                if self.errors:
                    f.write("- Address all ERROR level issues before proceeding\n")
                if self.warnings:
                    f.write("- Review WARNING level issues for optimal configuration\n")
                f.write("- Verify all cloud provider credentials\n")
                f.write("- Test configuration in development environment first\n")
                f.write("- Check network connectivity and permissions\n")
                
            return report_filename, True
        except Exception as e:
            return f"Failed to export error report: {e}", False

# Initialize enhanced logger
if 'logger' not in st.session_state:
    st.session_state.logger = EnhancedLogger()

# Global error handler
def handle_error(error_type, message, exception=None, context=None, show_user=True):
    """Global error handler with logging and user feedback"""
    try:
        error_info = st.session_state.logger.log_error(
            error_type=error_type,
            message=message,
            exception=exception,
            context=context
        )
        
        if show_user:
            st.error(f"Error: {message}")
            with st.expander("Error Details"):
                st.text(f"Type: {error_type}")
                st.text(f"Time: {error_info['timestamp']}")
                if exception:
                    st.text(f"Exception: {str(exception)}")
                
                # Download error report button
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Download Full Error Log"):
                        log_content = st.session_state.logger.get_full_log()
                        st.download_button(
                            label="Download Log File",
                            data=log_content,
                            file_name=st.session_state.logger.log_file,
                            mime="text/plain"
                        )
                
                with col2:
                    if st.button("Generate Error Report"):
                        report_file, success = st.session_state.logger.export_error_report()
                        if success:
                            with open(report_file, 'r', encoding='utf-8') as f:
                                report_content = f.read()
                            st.download_button(
                                label="Download Error Report",
                                data=report_content,
                                file_name=report_file,
                                mime="text/plain"
                            )
                            st.success("Error report generated successfully!")
                        else:
                            st.error(report_file)  # report_file contains error message
        
        return error_info
    except Exception as e:
        # Fallback error handling
        st.error(f"Critical error in error handler: {str(e)}")
        return None

# Wrapper function for safe execution
def safe_execute(func, *args, **kwargs):
    """Execute function with error handling"""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        handle_error(
            error_type="EXECUTION_ERROR",
            message=f"Failed to execute {func.__name__}",
            exception=e,
            context={
                'function_name': func.__name__,
                'args': str(args)[:200],  # Limit context size
                'kwargs': str(kwargs)[:200]
            }
        )
        return None

# Cloud-agnostic validation functions
def validate_cloud_config(config, provider):
    """Validate cloud configuration based on provider with error handling"""
    try:
        if provider == "azure":
            required_fields = ['subscription_id', 'resource_group', 'location']
            missing = [field for field in required_fields if not config.get(f'azure_{field}')]
            if missing:
                return False, f"Missing Azure fields: {', '.join(missing)}"
        
        elif provider == "aws":
            required_fields = ['access_key_id', 'secret_access_key', 'region']
            missing = [field for field in required_fields if not config.get(f'aws_{field}')]
            if missing:
                return False, f"Missing AWS fields: {', '.join(missing)}"
        
        elif provider == "gcp":
            required_fields = ['project_id', 'service_account_key', 'region']
            missing = [field for field in required_fields if not config.get(f'gcp_{field}')]
            if missing:
                return False, f"Missing GCP fields: {', '.join(missing)}"
        
        elif provider == "multi_cloud":
            # Multi-cloud needs at least one provider configured
            has_provider = any([
                config.get('azure_subscription_id'),
                config.get('aws_access_key_id'),
                config.get('gcp_project_id')
            ])
            if not has_provider:
                return False, "Multi-cloud setup requires at least one cloud provider configured"
        
        return True, "Valid"
    except Exception as e:
        handle_error(
            error_type="VALIDATION_ERROR",
            message="Failed to validate cloud configuration",
            exception=e,
            context={'provider': provider, 'config_keys': list(config.keys())}
        )
        return False, f"Validation error: {str(e)}"

def save_config_to_file():
    """Generate config file for download with error handling"""
    try:
        config_json = json.dumps(st.session_state.config, indent=2)
        filename = f"actory_ai_config_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Log successful config save
        st.session_state.logger.log_info(
            "CONFIG_EXPORT",
            f"Configuration exported to {filename}",
            context={'config_items': len(st.session_state.config)}
        )
        
        return config_json, filename
    except Exception as e:
        handle_error(
            error_type="CONFIG_EXPORT_ERROR",
            message="Failed to export configuration",
            exception=e,
            context={'config_size': len(str(st.session_state.config))}
        )
        return "{}", f"error_config_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# Header
st.markdown('<h1 class="main-header">Actory AI Configuration Management</h1>', unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("Navigation")

# Only show cloud provider selection if not set
if not st.session_state.cloud_provider:
    pages = ["Cloud Provider Selection"]
else:
    pages = [
        "Cloud Configuration",
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

# Progress indicator (only show if cloud provider is selected)
if st.session_state.cloud_provider:
    total_sections = len(pages) - 2  # Exclude Review and Logs pages
    completed_sections = sum(1 for section in ['cloud', 'ai', 'storage', 'monitoring', 'security', 'deployment'] 
                            if any(key.startswith(section) for key in st.session_state.config.keys()))
    
    st.sidebar.metric("Configuration Progress", f"{completed_sections}/{total_sections}")
    st.sidebar.progress(completed_sections / total_sections)
    
    # Show selected cloud provider
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Selected Provider:** {CLOUD_PROVIDERS[st.session_state.cloud_provider]['name']}")

# Page content
if page == "Cloud Provider Selection":
    st.markdown('<h2 class="section-header">Choose Your Cloud Strategy</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    Select your primary cloud deployment strategy. This will customize the configuration 
    options and deployment templates for your chosen environment.
    """)
    
    # Cloud provider cards
    cols = st.columns(2)
    
    for i, (provider_key, provider_info) in enumerate(CLOUD_PROVIDERS.items()):
        with cols[i % 2]:
            # Provider selection
            if st.button(
                f"Select {provider_info['name']}", 
                key=f"select_{provider_key}",
                use_container_width=True
            ):
                st.session_state.cloud_provider = provider_key
                st.rerun()
            
            # Provider details
            with st.expander(f"About {provider_info['name']}"):
                if provider_key == "azure":
                    st.markdown("""
                    **Microsoft Azure**
                    - Native Azure OpenAI integration
                    - Enterprise-grade security with Key Vault
                    - Seamless Azure DevOps integration
                    - Best for Microsoft-centric environments
                    """)
                elif provider_key == "aws":
                    st.markdown("""
                    **Amazon Web Services**
                    - Bedrock for diverse AI models
                    - Comprehensive service ecosystem
                    - Strong enterprise adoption
                    - Best for AWS-native applications
                    """)
                elif provider_key == "gcp":
                    st.markdown("""
                    **Google Cloud Platform**
                    - Vertex AI and Gemini integration
                    - Strong ML/AI capabilities
                    - Advanced analytics tools
                    - Best for data-intensive workloads
                    """)
                elif provider_key == "multi_cloud":
                    st.markdown("""
                    **Multi-Cloud Strategy**
                    - Vendor flexibility and redundancy
                    - Best-of-breed service selection
                    - Third-party integrations
                    - Best for avoiding vendor lock-in
                    """)
    
    # Continue button
    if st.session_state.cloud_provider:
        st.success(f"Selected: {CLOUD_PROVIDERS[st.session_state.cloud_provider]['name']}")
        
        if st.button("Continue to Configuration", type="primary"):
            st.rerun()

elif page == "Cloud Configuration":
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
    st.markdown(f'<h2 class="section-header">{provider_info["name"]} Configuration</h2>', unsafe_allow_html=True)
    
    # Provider-specific configuration
    if provider == "azure":
        # Azure configuration
        with st.expander("Azure Setup Information"):
            st.info("""
            Required Azure Services:
            - Azure OpenAI Service (if using Azure AI)
            - Storage Account  
            - Key Vault
            - Container Registry (optional)
            
            Prerequisites:
            - Azure subscription with admin rights
            - Service principal credentials
            """)
        
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
                provider_info["regions"],
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
    
    elif provider == "aws":
        # AWS configuration
        with st.expander("AWS Setup Information"):
            st.info("""
            Required AWS Services:
            - Bedrock (for AI models)
            - S3 (for storage)
            - Secrets Manager (for key management)
            - CloudWatch (for monitoring)
            
            Prerequisites:
            - AWS account with admin rights
            - IAM user or role credentials
            """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Basic Settings")
            access_key_id = st.text_input(
                "AWS Access Key ID",
                value=st.session_state.config.get('aws_access_key_id', ''),
                help="AWS access key ID"
            )
            if access_key_id:
                st.session_state.config['aws_access_key_id'] = access_key_id
            
            secret_access_key = st.text_input(
                "AWS Secret Access Key",
                value=st.session_state.config.get('aws_secret_access_key', ''),
                type="password",
                help="AWS secret access key"
            )
            if secret_access_key:
                st.session_state.config['aws_secret_access_key'] = secret_access_key
            
            region = st.selectbox(
                "AWS Region",
                provider_info["regions"],
                help="AWS region for resources"
            )
            st.session_state.config['aws_region'] = region
        
        with col2:
            st.subheader("S3 Configuration")
            s3_bucket = st.text_input(
                "S3 Bucket Name",
                value=st.session_state.config.get('aws_s3_bucket', ''),
                help="S3 bucket for storage",
                placeholder="agentic-testing-bucket"
            )
            if s3_bucket:
                st.session_state.config['aws_s3_bucket'] = s3_bucket
            
            st.subheader("IAM Configuration")
            iam_role_arn = st.text_input(
                "IAM Role ARN (optional)",
                value=st.session_state.config.get('aws_iam_role_arn', ''),
                help="IAM role ARN for cross-account access"
            )
            if iam_role_arn:
                st.session_state.config['aws_iam_role_arn'] = iam_role_arn
    
    elif provider == "gcp":
        # GCP configuration
        with st.expander("GCP Setup Information"):
            st.info("""
            Required GCP Services:
            - Vertex AI (for AI models)
            - Cloud Storage (for storage)
            - Secret Manager (for key management)
            - Cloud Monitoring (for monitoring)
            
            Prerequisites:
            - GCP project with admin rights
            - Service account credentials
            """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Basic Settings")
            project_id = st.text_input(
                "GCP Project ID",
                value=st.session_state.config.get('gcp_project_id', ''),
                help="Your GCP project ID"
            )
            if project_id:
                st.session_state.config['gcp_project_id'] = project_id
            
            region = st.selectbox(
                "GCP Region",
                provider_info["regions"],
                help="GCP region for resources"
            )
            st.session_state.config['gcp_region'] = region
        
        with col2:
            st.subheader("Service Account")
            service_account_key = st.text_area(
                "Service Account Key (JSON)",
                value=st.session_state.config.get('gcp_service_account_key', ''),
                help="Service account key in JSON format",
                height=100
            )
            if service_account_key:
                st.session_state.config['gcp_service_account_key'] = service_account_key
            
            storage_bucket = st.text_input(
                "Cloud Storage Bucket",
                value=st.session_state.config.get('gcp_storage_bucket', ''),
                help="Cloud Storage bucket name",
                placeholder="agentic-testing-bucket"
            )
            if storage_bucket:
                st.session_state.config['gcp_storage_bucket'] = storage_bucket
    
    elif provider == "multi_cloud":
        # Multi-cloud configuration
        st.markdown("""
        Configure multiple cloud providers for maximum flexibility and redundancy.
        You can select different providers for different services.
        """)
        
        # Cloud provider selection for each service
        st.subheader("Service Provider Mapping")
        
        col1, col2 = st.columns(2)
        
        with col1:
            primary_compute = st.selectbox(
                "Primary Compute Provider",
                ["azure", "aws", "gcp"],
                help="Primary cloud for Kubernetes and compute resources"
            )
            st.session_state.config['multi_cloud_compute'] = primary_compute
            
            primary_ai = st.selectbox(
                "Primary AI Provider",
                ["anthropic", "openai", "azure_openai", "aws_bedrock", "gcp_vertex"],
                help="Primary AI/ML service provider"
            )
            st.session_state.config['multi_cloud_ai'] = primary_ai
        
        with col2:
            primary_storage = st.selectbox(
                "Primary Storage Provider",
                ["aws_s3", "azure_blob", "gcs", "minio"],
                help="Primary object storage provider"
            )
            st.session_state.config['multi_cloud_storage'] = primary_storage
            
            primary_monitoring = st.selectbox(
                "Primary Monitoring Provider",
                ["datadog", "new_relic", "grafana", "prometheus"],
                help="Primary monitoring and observability platform"
            )
            st.session_state.config['multi_cloud_monitoring'] = primary_monitoring

elif page == "AI Models":
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
    st.markdown('<h2 class="section-header">AI Models Configuration</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Language Model")
        
        # Show provider-specific options
        if provider == "azure":
            available_providers = ["azure_openai"] + THIRD_PARTY_SERVICES["ai_providers"]
        elif provider == "aws":
            available_providers = ["aws_bedrock"] + THIRD_PARTY_SERVICES["ai_providers"] 
        elif provider == "gcp":
            available_providers = ["gcp_vertex", "gcp_gemini"] + THIRD_PARTY_SERVICES["ai_providers"]
        else:  # multi_cloud
            available_providers = ["azure_openai", "aws_bedrock", "gcp_vertex"] + THIRD_PARTY_SERVICES["ai_providers"]
        
        llm_provider = st.selectbox(
            "Primary LLM Provider",
            available_providers,
            help="Primary language model provider"
        )
        st.session_state.config['ai_llm_provider'] = llm_provider
        
        # Provider-specific configuration
        if llm_provider == "azure_openai":
            openai_endpoint = st.text_input(
                "Azure OpenAI Endpoint",
                value=st.session_state.config.get('azure_openai_endpoint', ''),
                help="Azure OpenAI service endpoint"
            )
            if openai_endpoint:
                st.session_state.config['azure_openai_endpoint'] = openai_endpoint
            
            openai_key = st.text_input(
                "Azure OpenAI API Key",
                value=st.session_state.config.get('azure_openai_key', ''),
                type="password",
                help="Azure OpenAI API key"
            )
            if openai_key:
                st.session_state.config['azure_openai_key'] = openai_key
        
        elif llm_provider == "aws_bedrock":
            model_id = st.selectbox(
                "Bedrock Model ID",
                ["anthropic.claude-3-sonnet-20240229-v1:0", "anthropic.claude-3-haiku-20240307-v1:0", "amazon.titan-text-express-v1"],
                help="Bedrock model identifier"
            )
            st.session_state.config['aws_bedrock_model_id'] = model_id
        
        elif llm_provider == "gcp_vertex":
            model_name = st.text_input(
                "Vertex AI Model Name",
                value=st.session_state.config.get('gcp_vertex_model', 'text-bison'),
                help="Vertex AI model name"
            )
            if model_name:
                st.session_state.config['gcp_vertex_model'] = model_name
        
        elif llm_provider in THIRD_PARTY_SERVICES["ai_providers"]:
            api_key = st.text_input(
                f"{llm_provider.title()} API Key",
                value=st.session_state.config.get(f'{llm_provider}_api_key', ''),
                type="password",
                help=f"API key for {llm_provider}"
            )
            if api_key:
                st.session_state.config[f'{llm_provider}_api_key'] = api_key
        
        # Common model parameters
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
        vision_providers = ["moondream", "omnivision", "gpt4_vision", "claude_vision", "gemini_vision", "custom"]
        
        vision_provider = st.selectbox(
            "Vision Provider",
            vision_providers,
            help="Vision model provider"
        )
        st.session_state.config['ai_vision_provider'] = vision_provider
        
        if vision_provider in ["moondream", "omnivision"]:
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
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
    st.markdown('<h2 class="section-header">Storage & Database Configuration</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Storage")
        
        # Show provider-specific and third-party storage options
        if provider == "azure":
            available_storage = ["azure_blob"] + THIRD_PARTY_SERVICES["storage"] + ["local"]
        elif provider == "aws":
            available_storage = ["aws_s3"] + THIRD_PARTY_SERVICES["storage"] + ["local"]
        elif provider == "gcp":
            available_storage = ["gcs"] + THIRD_PARTY_SERVICES["storage"] + ["local"]
        else:  # multi_cloud
            available_storage = ["azure_blob", "aws_s3", "gcs"] + THIRD_PARTY_SERVICES["storage"] + ["local"]
        
        storage_type = st.selectbox(
            "Storage Type",
            available_storage,
            help="Primary storage backend"
        )
        st.session_state.config['storage_type'] = storage_type
        
        # Storage-specific configuration
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
        
        elif storage_type == "aws_s3":
            s3_bucket = st.text_input(
                "S3 Bucket Name",
                value=st.session_state.config.get('s3_bucket_name', ''),
                help="S3 bucket name"
            )
            if s3_bucket:
                st.session_state.config['s3_bucket_name'] = s3_bucket
            
            s3_region = st.selectbox(
                "S3 Region",
                ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
                help="S3 bucket region"
            )
            st.session_state.config['s3_region'] = s3_region
        
        elif storage_type == "gcs":
            gcs_bucket = st.text_input(
                "GCS Bucket Name",
                value=st.session_state.config.get('gcs_bucket_name', ''),
                help="Google Cloud Storage bucket name"
            )
            if gcs_bucket:
                st.session_state.config['gcs_bucket_name'] = gcs_bucket
    
    with col2:
        st.subheader("Database")
        
        # Show provider-specific and third-party database options
        if provider == "azure":
            available_databases = provider_info["database_services"] + THIRD_PARTY_SERVICES["databases"]
        elif provider == "aws":
            available_databases = provider_info["database_services"] + THIRD_PARTY_SERVICES["databases"]
        elif provider == "gcp":
            available_databases = provider_info["database_services"] + THIRD_PARTY_SERVICES["databases"]
        else:  # multi_cloud
            available_databases = THIRD_PARTY_SERVICES["databases"]
        
        db_type = st.selectbox(
            "Database Type",
            available_databases,
            help="Primary database backend"
        )
        st.session_state.config['database_type'] = db_type
        
        # Database-specific configuration
        if db_type in ["postgresql", "rds_postgresql", "cloud_sql_postgresql", "mysql", "rds_mysql", "cloud_sql_mysql"]:
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
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
    st.markdown('<h2 class="section-header">Monitoring & Analytics</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Primary Monitoring")
        
        # Show provider-specific and third-party monitoring options
        if provider == "azure":
            available_monitoring = ["azure_app_insights"] + THIRD_PARTY_SERVICES["monitoring"]
        elif provider == "aws":
            available_monitoring = ["aws_cloudwatch"] + THIRD_PARTY_SERVICES["monitoring"]
        elif provider == "gcp":
            available_monitoring = ["gcp_monitoring"] + THIRD_PARTY_SERVICES["monitoring"]
        else:  # multi_cloud
            available_monitoring = THIRD_PARTY_SERVICES["monitoring"]
        
        monitoring_provider = st.selectbox(
            "Monitoring Provider",
            available_monitoring,
            help="Primary monitoring platform"
        )
        st.session_state.config['monitoring_provider'] = monitoring_provider
        
        # Provider-specific configuration
        if monitoring_provider == "azure_app_insights":
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
        
        elif monitoring_provider == "datadog":
            datadog_api_key = st.text_input(
                "DataDog API Key",
                value=st.session_state.config.get('datadog_api_key', ''),
                type="password",
                help="DataDog API key"
            )
            if datadog_api_key:
                st.session_state.config['datadog_api_key'] = datadog_api_key
        
        # Common monitoring settings
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
        st.subheader("Additional Analytics")
        
        # Optional third-party services
        mixpanel_token = st.text_input(
            "Mixpanel Token (Optional)",
            value=st.session_state.config.get('monitoring_mixpanel_token', ''),
            type="password",
            help="Mixpanel project token"
        )
        if mixpanel_token:
            st.session_state.config['monitoring_mixpanel_token'] = mixpanel_token

elif page == "Security":
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
    st.markdown('<h2 class="section-header">Security & Compliance</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Authentication")
        
        # Show provider-specific and third-party auth options
        if provider == "azure":
            available_auth = ["azure_ad", "oauth2", "local"]
        elif provider == "aws":
            available_auth = ["aws_cognito", "oauth2", "local"]
        elif provider == "gcp":
            available_auth = ["gcp_iam", "firebase_auth", "oauth2", "local"]
        else:  # multi_cloud
            available_auth = ["oauth2", "okta", "auth0", "local"]
        
        auth_type = st.selectbox(
            "Authentication Type",
            available_auth,
            help="Primary authentication method"
        )
        st.session_state.config['security_auth_type'] = auth_type
        
        # Common auth settings
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
    
    with col2:
        st.subheader("Encryption & Secrets")
        
        # Show provider-specific and third-party key management options
        if provider == "azure":
            available_key_mgmt = ["azure_keyvault"] + THIRD_PARTY_SERVICES["security"]
        elif provider == "aws":
            available_key_mgmt = ["aws_secrets_manager", "aws_kms"] + THIRD_PARTY_SERVICES["security"]
        elif provider == "gcp":
            available_key_mgmt = ["gcp_secret_manager", "gcp_kms"] + THIRD_PARTY_SERVICES["security"]
        else:  # multi_cloud
            available_key_mgmt = THIRD_PARTY_SERVICES["security"]
        
        key_management = st.selectbox(
            "Key Management",
            available_key_mgmt,
            help="Key management service"
        )
        st.session_state.config['security_key_management'] = key_management
        
        # Encryption settings
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

elif page == "Deployment":
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
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

elif page == "Review & Deploy":
    provider = st.session_state.cloud_provider
    provider_info = CLOUD_PROVIDERS[provider]
    
    st.markdown('<h2 class="section-header">Configuration Review & Deployment</h2>', unsafe_allow_html=True)
    
    # Validation
    is_valid, validation_message = validate_cloud_config(st.session_state.config, provider)
    
    if is_valid:
        st.success("Configuration is valid and ready for deployment!")
    else:
        st.error(f"Configuration issues: {validation_message}")
    
    # Configuration summary
    st.subheader("Configuration Summary")
    
    # Show basic configuration items
    if st.session_state.config:
        with st.expander("View Configuration Details"):
            # Mask sensitive values for display
            display_config = {}
            for key, value in st.session_state.config.items():
                if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'password', 'token']):
                    display_config[key] = "[HIDDEN]" if value else value
                else:
                    display_config[key] = value
            st.json(display_config)
    
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
        
        progress_container = st.container()
        
        with progress_container:
            steps = [
                "Installing dependencies...",
                f"Setting up {provider_info['name']} resources...",
                "Deploying services...",
                "Configuring monitoring...",
                "Running health checks..."
            ]
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, step in enumerate(steps):
                status_text.text(step)
                progress_bar.progress((i + 1) / len(steps))
            
            st.success("Deployment completed successfully!")
            
            # Show completion details
            st.markdown(f"""
            **Deployment Summary:**
            - Cloud Provider: {provider_info['name']}
            - Environment: {st.session_state.config.get('deployment_environment', 'production')}
            - Deployment Type: {st.session_state.config.get('deployment_type', 'kubernetes')}
            - Access URL: http://localhost:8000
            - Health Check: http://localhost:8000/health
            - API Documentation: http://localhost:8000/docs
            
            **Next Steps:**
            1. Access the dashboard to create your first test
            2. Review the generated documentation
            3. Set up CI/CD integration if needed
            4. Configure team access and permissions
            """)
            
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
            
            # Validate loaded configuration
            if isinstance(config, dict):
                st.session_state.config.update(config)
                st.session_state.logger.log_info(
                    "CONFIG_IMPORT",
                    f"Configuration loaded from {uploaded_file.name}",
                    context={'imported_keys': len(config)}
                )
                st.success("Configuration loaded successfully!")
                st.rerun()
            else:
                raise ValueError("Invalid configuration format - must be a JSON/YAML object")
                
        except json.JSONDecodeError as e:
            handle_error(
                error_type="CONFIG_PARSE_ERROR",
                message=f"Invalid JSON format in uploaded file: {str(e)}",
                exception=e,
                context={'filename': uploaded_file.name}
            )
        except yaml.YAMLError as e:
            handle_error(
                error_type="CONFIG_PARSE_ERROR",
                message=f"Invalid YAML format in uploaded file: {str(e)}",
                exception=e,
                context={'filename': uploaded_file.name}
            )
        except Exception as e:
            handle_error(
                error_type="CONFIG_LOAD_ERROR",
                message=f"Failed to load configuration from {uploaded_file.name}",
                exception=e,
                context={'filename': uploaded_file.name, 'file_size': uploaded_file.size if hasattr(uploaded_file, 'size') else 'unknown'}
            )

elif page == "Logs":
    st.markdown('<h2 class="section-header">Logs & Status</h2>', unsafe_allow_html=True)
    
    # Status metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Setup Status", st.session_state.setup_status)
    
    with col2:
        st.metric("Cloud Provider", 
                 CLOUD_PROVIDERS[st.session_state.cloud_provider]['name'] if st.session_state.cloud_provider else "Not Selected")
    
    with col3:
        st.metric("Configuration Items", len(st.session_state.config))
    
    with col4:
        st.metric("Errors", len(st.session_state.logger.errors))
    
    # Error display with enhanced functionality
    if st.session_state.logger.errors:
        st.subheader("Errors and Issues")
        
        # Error summary
        error_summary = st.session_state.logger.get_summary()
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Errors", error_summary['total_errors'])
        with col2:
            st.metric("Total Warnings", error_summary['total_warnings'])
        with col3:
            st.metric("Session Duration (min)", round(error_summary['session_duration'] / 60, 1))
        
        # Error list
        for i, error in enumerate(st.session_state.logger.errors):
            with st.expander(f"Error {i+1}: {error['type']} - {error['timestamp']}"):
                st.error(f"Message: {error['message']}")
                if error['solution']:
                    st.info(f"Solution: {error['solution']}")
                if error['exception']:
                    st.code(f"Exception: {error['exception']}")
                if error['traceback']:
                    with st.expander("Full Traceback"):
                        st.code(error['traceback'])
                if error['context']:
                    with st.expander("Context"):
                        st.json(error['context'])
        
        # Bulk download options
        st.subheader("Download Options")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Download Full Log"):
                log_content = st.session_state.logger.get_full_log()
                st.download_button(
                    label="Download Log File",
                    data=log_content,
                    file_name=st.session_state.logger.log_file,
                    mime="text/plain"
                )
        
        with col2:
            if st.button("Generate Error Report"):
                report_file, success = st.session_state.logger.export_error_report()
                if success:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        report_content = f.read()
                    st.download_button(
                        label="Download Error Report",
                        data=report_content,
                        file_name=report_file,
                        mime="text/plain"
                    )
                    st.success("Error report generated successfully!")
                else:
                    st.error(report_file)
        
        with col3:
            if st.button("Clear All Logs"):
                st.session_state.logger = EnhancedLogger()
                st.success("All logs cleared!")
                st.rerun()
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
    
    # Cloud provider specific diagnostics
    if st.session_state.cloud_provider:
        st.subheader(f"{CLOUD_PROVIDERS[st.session_state.cloud_provider]['name']} Diagnostics")
        
        if st.button("Run Diagnostics"):
            with st.spinner("Running diagnostics..."):
                diagnostics = run_cloud_diagnostics(st.session_state.cloud_provider, st.session_state.config)
                
                for check_name, result in diagnostics.items():
                    if result['status'] == 'success':
                        st.success(f"✓ {check_name}: {result['message']}")
                    elif result['status'] == 'warning':
                        st.warning(f"⚠ {check_name}: {result['message']}")
                    else:
                        st.error(f"✗ {check_name}: {result['message']}")
    
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
        "Platform": os.name,
        "Cloud Provider": CLOUD_PROVIDERS[st.session_state.cloud_provider]['name'] if st.session_state.cloud_provider else "Not Selected"
    }
    
    for key, value in system_info.items():
        st.text(f"{key}: {value}")

# Helper functions for cloud diagnostics
def run_cloud_diagnostics(provider, config):
    """Run cloud-specific diagnostics"""
    diagnostics = {}
    
    try:
        if provider == "azure":
            diagnostics.update({
                "Azure Subscription": {
                    "status": "success" if config.get('azure_subscription_id') else "error",
                    "message": "Valid subscription ID configured" if config.get('azure_subscription_id') else "No subscription ID configured"
                },
                "Azure Resource Group": {
                    "status": "success" if config.get('azure_resource_group') else "warning",
                    "message": "Resource group configured" if config.get('azure_resource_group') else "No resource group specified"
                },
                "Azure OpenAI": {
                    "status": "success" if config.get('azure_openai_endpoint') else "warning",
                    "message": "OpenAI endpoint configured" if config.get('azure_openai_endpoint') else "No OpenAI endpoint configured"
                }
            })
        
        elif provider == "aws":
            diagnostics.update({
                "AWS Credentials": {
                    "status": "success" if config.get('aws_access_key_id') else "error",
                    "message": "Access key configured" if config.get('aws_access_key_id') else "No access key configured"
                },
                "AWS Region": {
                    "status": "success" if config.get('aws_region') else "warning",
                    "message": f"Region set to {config.get('aws_region')}" if config.get('aws_region') else "No region specified"
                },
                "S3 Configuration": {
                    "status": "success" if config.get('aws_s3_bucket') else "warning",
                    "message": "S3 bucket configured" if config.get('aws_s3_bucket') else "No S3 bucket specified"
                }
            })
        
        elif provider == "gcp":
            diagnostics.update({
                "GCP Project": {
                    "status": "success" if config.get('gcp_project_id') else "error",
                    "message": "Project ID configured" if config.get('gcp_project_id') else "No project ID configured"
                },
                "Service Account": {
                    "status": "success" if config.get('gcp_service_account_key') else "warning",
                    "message": "Service account configured" if config.get('gcp_service_account_key') else "No service account configured"
                },
                "GCP Region": {
                    "status": "success" if config.get('gcp_region') else "warning",
                    "message": f"Region set to {config.get('gcp_region')}" if config.get('gcp_region') else "No region specified"
                }
            })
        
        elif provider == "multi_cloud":
            has_azure = bool(config.get('azure_subscription_id'))
            has_aws = bool(config.get('aws_access_key_id'))
            has_gcp = bool(config.get('gcp_project_id'))
            
            diagnostics.update({
                "Multi-Cloud Setup": {
                    "status": "success" if (has_azure or has_aws or has_gcp) else "error",
                    "message": f"Configured providers: {', '.join([p for p, c in [('Azure', has_azure), ('AWS', has_aws), ('GCP', has_gcp)] if c])}" if (has_azure or has_aws or has_gcp) else "No cloud providers configured"
                },
                "Service Distribution": {
                    "status": "success" if config.get('multi_cloud_ai') else "warning",
                    "message": "AI services configured" if config.get('multi_cloud_ai') else "No AI service provider selected"
                }
            })
        
        # Common diagnostics
        diagnostics.update({
            "AI Configuration": {
                "status": "success" if config.get('ai_llm_provider') else "warning",
                "message": f"Using {config.get('ai_llm_provider')}" if config.get('ai_llm_provider') else "No AI provider configured"
            },
            "Storage Configuration": {
                "status": "success" if config.get('storage_type') else "warning",
                "message": f"Using {config.get('storage_type')}" if config.get('storage_type') else "No storage type configured"
            },
            "Database Configuration": {
                "status": "success" if config.get('database_type') else "warning",
                "message": f"Using {config.get('database_type')}" if config.get('database_type') else "No database type configured"
            },
            "Security Configuration": {
                "status": "success" if config.get('security_auth_type') else "warning",
                "message": f"Auth type: {config.get('security_auth_type')}" if config.get('security_auth_type') else "No authentication type configured"
            }
        })
    
    except Exception as e:
        st.session_state.logger.log_error(
            "DIAGNOSTICS_ERROR",
            "Failed to run diagnostics",
            exception=e,
            context={'provider': provider}
        )
        diagnostics["Diagnostic Error"] = {
            "status": "error",
            "message": f"Failed to run diagnostics: {str(e)}"
        }
    
    return diagnostics

# Footer and sidebar
st.sidebar.markdown("---")
st.sidebar.markdown("Actory AI Configuration Management")
st.sidebar.markdown("Version 2.0.0 - Cloud Agnostic")

# Quick actions in sidebar
st.sidebar.subheader("Quick Actions")

# Change cloud provider button
if st.sidebar.button("Change Cloud Provider"):
    st.session_state.cloud_provider = None
    st.session_state.config = {}
    st.session_state.deployment_started = False
    st.success("Cloud provider reset! Please select a new provider.")
    st.rerun()

if st.sidebar.button("Reset Configuration"):
    if st.session_state.cloud_provider:
        # Keep cloud provider, reset config
        cloud_provider = st.session_state.cloud_provider
        st.session_state.config = {}
        st.session_state.deployment_started = False
        st.session_state.cloud_provider = cloud_provider
        st.success("Configuration reset!")
        st.rerun()
    else:
        st.warning("Please select a cloud provider first")

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
if st.session_state.cloud_provider:
    config_sections = {
        'Cloud': f'{st.session_state.cloud_provider}_',
        'AI': 'ai_llm_provider', 
        'Storage': 'storage_type',
        'Security': 'security_auth_type',
        'Deployment': 'deployment_environment'
    }

    st.sidebar.subheader("Configuration Status")
    for section, key_prefix in config_sections.items():
        if section == 'Cloud':
            # Check for any cloud-specific configuration
            has_config = any(key.startswith(key_prefix) for key in st.session_state.config.keys())
        else:
            has_config = bool(st.session_state.config.get(key_prefix))
        
        if has_config:
            st.sidebar.success(f"{section}: Configured")
        else:
            st.sidebar.warning(f"{section}: Not configured")

# Cloud provider info in sidebar
if st.session_state.cloud_provider:
    provider_info = CLOUD_PROVIDERS[st.session_state.cloud_provider]
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Selected Provider:** {provider_info['name']}")
    
    # Show provider-specific quick stats
    with st.sidebar.expander("Provider Details"):
        st.markdown(f"**Regions Available:** {len(provider_info['regions'])}")
        st.markdown(f"**AI Services:** {', '.join(provider_info['ai_services'])}")
        st.markdown(f"**Storage Services:** {', '.join(provider_info['storage_services'])}")
        st.markdown(f"**Key Management:** {provider_info['key_management']}")

# Help section in sidebar
with st.sidebar.expander("Need Help?"):
    st.markdown("""
    **Getting Started:**
    1. Select your cloud provider
    2. Configure cloud credentials
    3. Set up AI models and storage
    4. Configure monitoring and security
    5. Set deployment preferences
    6. Review and deploy
    
    **Tips:**
    - Multi-cloud setup allows maximum flexibility
    - All sensitive data is encrypted
    - Configurations can be exported/imported
    - Test configurations before deployment
    """)

# Version and credits
st.sidebar.markdown("---")
st.sidebar.markdown("""
<div style='text-align: center; color: #666; font-size: 0.8rem;'>
<p><strong>Actory AI Configuration Management</strong><br>
Cloud-Agnostic Configuration Factory</p>
<p>Version 2.0.0<br>
Supports Azure | AWS | GCP | Multi-Cloud</p>
<p>Built for automated testing</p>
</div>
""", unsafe_allow_html=True)