#!/bin/bash

# OWASP LLM Top 10 Testing Framework
# This script sets up the environment, installs dependencies, and runs tests

set -e  # Exit immediately if a command exits with a non-zero status

# Color codes for better readability
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

# Functions
print_section() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# Check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it to continue."
    else
        print_success "AWS CLI is installed"
    fi
}

# Check AWS credentials and region
check_aws_credentials() {
    print_section "Checking AWS credentials"
    echo "DEBUG: Entered check_aws_credentials"
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "DEBUG: aws sts get-caller-identity failed"
        print_error "AWS credentials not configured. Please run 'aws configure' first."
    else
        echo "DEBUG: aws sts get-caller-identity succeeded"
        print_success "AWS credentials are configured"
    fi
    
    # Get current AWS region
    AWS_REGION=$(aws configure get region)
    echo "DEBUG: AWS_REGION after aws configure get region: $AWS_REGION"
    if [ -z "$AWS_REGION" ]; then
        print_warning "AWS region not set. Using default region: us-east-1"
        AWS_REGION="us-east-1"
    else
        print_success "Using AWS region: $AWS_REGION"
    fi
    echo "DEBUG: Exiting check_aws_credentials"
}

# Check if parameter exists in AWS Parameter Store
check_parameter() {
    local param_name=$1
    local description=$2
    local secure=$3
    local env_var_name=$4
    
    print_section "Checking parameter: $param_name"
    
    # Try to get the parameter value
    if [ "$secure" = "true" ]; then
        param_value=$(aws ssm get-parameter --name "$param_name" --with-decryption --region "$AWS_REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "")
    else
        param_value=$(aws ssm get-parameter --name "$param_name" --region "$AWS_REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "")
    fi
    
    # If parameter doesn't exist or is empty, prompt for value
    if [ -z "$param_value" ]; then
        print_warning "Parameter $param_name not found or empty in region $AWS_REGION"
        echo -e "\n${YELLOW}$description${NC}"
        
        if [ "$secure" = "true" ]; then
            echo -e "Please enter value for $param_name (input will be hidden):"
            read -s param_value
            echo "" # Add a newline after hidden input
        else
            echo -e "Please enter value for $param_name:"
            read param_value
        fi
        
        # Confirm before saving to Parameter Store
        echo -e "\nDo you want to save this value to AWS Parameter Store? (y/n)"
        read save_response
        
        if [[ "$save_response" =~ ^[Yy] ]]; then
            if [ "$secure" = "true" ]; then
                aws ssm put-parameter --name "$param_name" --value "$param_value" --type "SecureString" --overwrite --region "$AWS_REGION"
            else
                aws ssm put-parameter --name "$param_name" --value "$param_value" --type "String" --overwrite --region "$AWS_REGION"
            fi
            print_success "Parameter $param_name saved to AWS Parameter Store in region $AWS_REGION"
        else
            print_warning "Parameter not saved to AWS Parameter Store. Using value for this session only."
        fi
    else
        print_success "Found parameter $param_name in AWS Parameter Store"
    fi
    
    # Export as environment variable using the provided env_var_name
    export "$env_var_name"="$param_value"
    print_success "Exported parameter as $env_var_name"
}

# Check required parameters
check_required_parameters() {
    print_section "Checking required parameters"
    echo "DEBUG: Entered check_required_parameters"
    # Check AWS credentials and region first
    check_aws_credentials
    echo "DEBUG: After check_aws_credentials in check_required_parameters"
    # Check OpenAI API key - use OPENAI_API_KEY as the environment variable name
    check_parameter "/owasp-llm-top10/OPENAI_API_KEY" "OpenAI API key is required for testing LLM vulnerabilities" "true" "OPENAI_API_KEY"
    
    # Add more parameters as needed
    # check_parameter "/owasp-llm-top10/OTHER_PARAM" "Description of parameter" "false" "ENV_VAR_NAME"
    echo "DEBUG: Exiting check_required_parameters"
}

check_python_version() {
    if command -v python3.11 &> /dev/null; then
        print_success "Python 3.11 is installed"
        PYTHON_CMD="python3.11"
    elif command -v python3 &> /dev/null && [[ $(python3 --version) == *"3.11"* ]]; then
        print_success "Python 3.11 is installed"
        PYTHON_CMD="python3"
    else
        print_warning "Python 3.11 is not installed or not the default. Using available Python version."
        print_warning "For best results, please install Python 3.11."
        PYTHON_CMD="python3"
    fi
}

setup_venv() {
    print_section "Setting up virtual environment"
    
    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists. Using existing environment."
    else
        $PYTHON_CMD -m venv venv
        print_success "Created virtual environment"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    print_success "Activated virtual environment"
    
    # Upgrade pip
    python -m pip install --upgrade pip
    print_success "Upgraded pip"
}

install_dependencies() {
    print_section "Installing dependencies"
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Installed dependencies from requirements.txt"
    else
        print_error "requirements.txt not found"
    fi
    
    # Install development dependencies
    pip install pytest pytest-cov
    print_success "Installed development dependencies"
}

run_tests() {
    print_section "Running tests"
    
    local test_module=$1
    
    # Ensure test-results directory exists
    mkdir -p test-results
    
    if [ -z "$test_module" ]; then
        # Run all tests
        python -m pytest tests/ --cov=src --cov-report=term --json-report --json-report-file=test-results/prompt_injection_test_results_$(date +"%Y%m%d_%H%M%S").json
    else
        # Run specific test module
        python -m pytest "tests/$test_module/" --cov="src/$test_module" --cov-report=term --json-report --json-report-file=test-results/prompt_injection_test_results_$(date +"%Y%m%d_%H%M%S").json
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Tests completed successfully"
    else
        print_error "Tests failed"
    fi
}

generate_report() {
    print_section "Generating test report"
    
    python scripts/generate_report.py --latest
    
    if [ $? -eq 0 ]; then
        print_success "Generated test report"
    else
        print_error "Failed to generate test report"
    fi
}

analyze_vulnerabilities() {
    print_section "Analyzing vulnerabilities"
    
    # Create test-results directory if it doesn't exist
    mkdir -p test-results
    
    # Run vulnerability analysis with debug flag
    python -m scripts.analyze_vulnerabilities --debug
    
    if [ $? -eq 0 ]; then
        print_success "Vulnerability analysis completed"
    else
        print_warning "Vulnerabilities detected"
    fi
}

run_specific_test() {
    local risk_number=$1
    
    if [ -z "$risk_number" ]; then
        print_error "Please specify a risk number (01-10)"
    fi
    
    # Validate risk number format
    if [[ ! $risk_number =~ ^[0-9]{2}$ ]]; then
        print_error "Risk number must be in format 01-10"
    fi
    
    # Check if the risk module exists - use a more flexible pattern matching
    if ! find src -type d -name "llm${risk_number}_*" | grep -q .; then
        print_error "Risk module llm${risk_number}_* not found"
    fi
    
    # Get the actual directory name
    risk_dir=$(find src -type d -name "llm${risk_number}_*" | head -n 1 | sed 's|src/||')
    
    print_section "Running tests for $risk_dir"
    run_tests "$risk_dir"
    generate_report
    analyze_vulnerabilities
}

run_demo() {
    print_section "Running prompt injection demo"

    # Check required parameters first
    check_required_parameters

    echo "DEBUG: After check_required_parameters in run_demo"
    set -x
    env
    ls -la
    pwd

    # Run the direct API demo script
    python3 scripts/direct_api_demo.py "${ARGS[@]:1}"

    # If scan results JSON exists, generate reports
    SCAN_JSON="test-results/prompt_injection_test_results_latest.json"
    if [ -f "$SCAN_JSON" ]; then
        echo "Generating formatted prompt injection reports..."
        python3 scripts/generate_prompt_injection_report.py "$SCAN_JSON"
    else
        echo "Warning: Scan results JSON ($SCAN_JSON) not found. Skipping report generation."
    fi

    if [ $? -eq 0 ]; then
        print_success "Demo completed successfully"
    else
        print_error "Demo failed"
    fi
}

set_github_token() {
  read -s -p "Enter your GitHub Personal Access Token: " GITHUB_TOKEN
  echo
  aws ssm put-parameter --name "/owasp-llm-top10/GITHUB_TOKEN" --value "$GITHUB_TOKEN" --type "SecureString" --overwrite
  echo "GitHub token stored in Parameter Store."
}

show_help() {
    echo -e "\n${BLUE}OWASP LLM Top 10 Testing Framework${NC}"
    echo -e "\nUsage: ./run.sh [command] [options]\n"
    echo -e "Commands:"
    echo -e "  setup\t\tSet up virtual environment and install dependencies"
    echo -e "  params\t\tCheck and update required AWS Parameter Store parameters"
    echo -e "  test [risk]\tRun tests (optionally for a specific risk, e.g., 01 for prompt injection)"
    echo -e "  demo\t\tRun prompt injection detection demo"
    echo -e "  report\t\tGenerate test report"
    echo -e "  analyze\t\tAnalyze vulnerabilities"
    echo -e "  all\t\tRun all tests, generate report, and analyze vulnerabilities"
    echo -e "  set-github-token\tSet GitHub token in AWS Parameter Store"
    echo -e "  help\t\tShow this help message"
    echo -e "\nExamples:"
    echo -e "  ./run.sh setup\t\tSet up the environment"
    echo -e "  ./run.sh params\tCheck and update required parameters"
    echo -e "  ./run.sh test\t\tRun all tests"
    echo -e "  ./run.sh demo\t\tRun the prompt injection demo"
    echo -e "  ./run.sh test 01\tRun tests for LLM01 (Prompt Injection)"
    echo -e "  ./run.sh all\t\tRun all tests and generate reports"
}

# Main script execution

# Capture all arguments at the top
ARGS=("$@")

# Make script executable if it's not already
if [ ! -x "$0" ]; then
    chmod +x "$0"
    print_success "Made script executable"
    exec "$0" "$@"  # Re-execute the script with the same arguments
    exit 0
 fi

# Check Python version
check_python_version

# Check if AWS CLI is installed
check_aws_cli

# Process commands
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

command=$1
shift

case $command in
    setup)
        setup_venv
        install_dependencies
        ;;
    params)
        check_required_parameters
        ;;
    test)
        # Check parameters before running tests
        check_required_parameters
        setup_venv
        if [ $# -eq 0 ]; then
            run_tests
        else
            run_specific_test "$1"
        fi
        ;;
    demo)
        run_demo
        ;;
    report)
        setup_venv
        generate_report
        ;;
    analyze)
        setup_venv
        analyze_vulnerabilities
        ;;
    all)
        # Check parameters before running all tests
        check_required_parameters
        setup_venv
        install_dependencies
        run_tests
        generate_report
        analyze_vulnerabilities
        ;;
    set-github-token)
        set_github_token
        ;;
    help)
        show_help
        ;;
    *)
        print_error "Unknown command: $command. Use './run.sh help' for usage information."
        ;;
esac

# Deactivate virtual environment
if [ -n "$VIRTUAL_ENV" ]; then
    deactivate
    print_success "Deactivated virtual environment"
fi

print_success "Script completed successfully"
