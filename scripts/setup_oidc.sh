#!/bin/bash

set -e

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m" # No Color

# Default values
REGION="us-east-1"
GITHUB_ORG=""
REPO_NAME=""
BRANCH_NAME="main"
GITHUB_TOKEN=""
OIDC_PROVIDER_ARN=""

# Function to print usage information
usage() {
  echo -e "${BOLD}Usage:${NC} $0 [options]"
  echo -e "\nSets up AWS OIDC authentication for GitHub Actions"
  echo -e "\n${BOLD}Options:${NC}"
  echo -e "  --region REGION            AWS region (default: us-east-1)"
  echo -e "  --github-org ORG_NAME      GitHub organization name (auto-detected if not provided)"
  echo -e "  --repo-name REPO_NAME      GitHub repository name (auto-detected if not provided)"
  echo -e "  --branch-name BRANCH_NAME  GitHub branch name (default: main)"
  echo -e "  --github-token TOKEN       GitHub personal access token (required)"
  echo -e "                             Token must have 'repo' and 'admin:repo_hook' permissions"
  echo -e "  --oidc-provider-arn ARN    ARN of the existing GitHub OIDC provider (optional)"
  echo -e "  --help                     Display this help message"
  exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)
      REGION="$2"
      shift 2
      ;;
    --github-org)
      GITHUB_ORG="$2"
      shift 2
      ;;
    --repo-name)
      REPO_NAME="$2"
      shift 2
      ;;
    --branch-name)
      BRANCH_NAME="$2"
      shift 2
      ;;
    --github-token)
      GITHUB_TOKEN="$2"
      shift 2
      ;;
    --oidc-provider-arn)
      OIDC_PROVIDER_ARN="$2"
      shift 2
      ;;
    --help)
      usage
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      usage
      ;;
  esac
done

# Retrieve GitHub token from Parameter Store if not set
if [[ -z "$GITHUB_TOKEN" ]]; then
  GITHUB_TOKEN=$(aws ssm get-parameter --name "/owasp-llm-top10/GITHUB_TOKEN" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo "")
fi

# Validate required parameters
if [[ -z "$GITHUB_TOKEN" ]]; then
  echo -e "${RED}Error: GitHub token is required.\n${YELLOW}Please run './run.sh set-github-token' to store your token in AWS Parameter Store, or provide it with --github-token.${NC}"
  usage
fi

# If GitHub org or repo name is not provided, try to extract from git remote URL
if [[ -z "$GITHUB_ORG" || -z "$REPO_NAME" ]]; then
  REMOTE_URL=$(git config --get remote.origin.url)
  if [[ $REMOTE_URL =~ github\.com[/:]([^/]+)/([^/.]+)(\.git)? ]]; then
    if [[ -z "$GITHUB_ORG" ]]; then
      GITHUB_ORG="${BASH_REMATCH[1]}"
      echo -e "${YELLOW}Auto-detected GitHub organization: $GITHUB_ORG${NC}"
    fi
    if [[ -z "$REPO_NAME" ]]; then
      REPO_NAME="${BASH_REMATCH[2]}"
      echo -e "${YELLOW}Auto-detected repository name: $REPO_NAME${NC}"
    fi
  else
    echo -e "${RED}Error: Could not auto-detect GitHub organization and repository name${NC}"
    echo -e "${RED}Please provide them using --github-org and --repo-name options${NC}"
    usage
  fi
fi

# Validate GitHub org and repo name
if [[ -z "$GITHUB_ORG" || -z "$REPO_NAME" ]]; then
  echo -e "${RED}Error: GitHub organization and repository name are required${NC}"
  usage
fi

# Dynamically generate stack name based on repo name
# Replace underscores with hyphens to comply with CloudFormation naming rules
SANITIZED_REPO_NAME=$(echo "$REPO_NAME" | tr '_' '-')
STACK_NAME="github-oidc-${SANITIZED_REPO_NAME}-stack"
echo -e "${YELLOW}Using stack name: $STACK_NAME${NC}"

# Create a temporary directory for CloudFormation template
TEMP_DIR=$(mktemp -d)
CFN_TEMPLATE="$TEMP_DIR/oidc-template.yaml"

# Create CloudFormation template
cat > "$CFN_TEMPLATE" << EOF
AWSTemplateFormatVersion: '2010-09-09'
Description: 'GitHub Actions OIDC Integration for AWS Authentication'

Parameters:
  GitHubOrg:
    Type: String
    Description: GitHub organization name
  RepoName:
    Type: String
    Description: GitHub repository name
  BranchName:
    Type: String
    Description: GitHub branch name
  OIDCProviderArn:
    Type: String
    Description: ARN of the existing GitHub OIDC provider
    Default: ''

Conditions:
  CreateOIDCProvider: !Equals [!Ref OIDCProviderArn, '']

Resources:
  GitHubOIDCProvider:
    Type: AWS::IAM::OIDCProvider
    Condition: CreateOIDCProvider
    Properties:
      Url: https://token.actions.githubusercontent.com
      ClientIdList: 
        - sts.amazonaws.com
      ThumbprintList:
        - 6938fd4d98bab03faadb97b34396831e3780aea1
      Tags:
        - Key: Project
          Value: !Sub "${GitHubOrg}-${RepoName}"
        - Key: ManagedBy
          Value: CloudFormation
        - Key: Environment
          Value: prod

  GitHubActionsRole:
    Type: AWS::IAM::Role
    Properties:
      # Use a predictable role name based on org and repo to avoid hardcoding random CloudFormation generated names
      # This makes it easier to reference in GitHub Actions workflows
      RoleName: !Join ['-', ['github-oidc-role', !Ref GitHubOrg, !Ref RepoName]]
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !If [CreateOIDCProvider, !GetAtt GitHubOIDCProvider.Arn, !Ref OIDCProviderArn]
            Action: 'sts:AssumeRoleWithWebIdentity'
            Condition:
              # The audience condition ensures the token is intended for AWS STS
              StringEquals:
                token.actions.githubusercontent.com:aud: 'sts.amazonaws.com'
              # Multiple patterns to match different GitHub Actions contexts
              StringLike:
                # Match workflows running on any branch, tag, or PR in this repo
                token.actions.githubusercontent.com:sub:
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:ref:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:environment:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:pull_request'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:workflow:*'
                  - !Sub 'repo:${GitHubOrg}/${RepoName}:branch:*'
      ManagedPolicyArns:
        - !Ref GitHubActionsPolicy
      Tags:
        - Key: Project
          Value: !Sub "${GitHubOrg}-${RepoName}"
        - Key: ManagedBy
          Value: CloudFormation
        - Key: Environment
          Value: prod

  GitHubActionsPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: !Sub 'Policy for GitHub Actions OIDC integration with ${GitHubOrg}/${RepoName}'
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:*'
              - 'iam:GetRole'
              - 'iam:CreateRole'
              - 'iam:AttachRolePolicy'
              - 'iam:PutRolePolicy'
              - 'logs:*'
              - 'ssm:*'
              - 's3:*'
            Resource: '*'

Outputs:
  RoleArn:
    Description: ARN of the IAM role for GitHub Actions
    Value: !GetAtt GitHubActionsRole.Arn
EOF

echo -e "\n${BOLD}Step 1:${NC} Deploying CloudFormation stack for OIDC integration..."

# Check if AWS CLI is installed and configured
if ! command -v aws &> /dev/null; then
  echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
  exit 1
fi

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
  echo -e "${RED}Error: AWS credentials are not configured. Please run 'aws configure' first.${NC}"
  exit 1
fi

# Check if GitHub OIDC provider already exists
echo -e "Checking for existing GitHub OIDC provider..."
EXISTING_PROVIDER=$(aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?contains(Arn, 'token.actions.githubusercontent.com')].Arn" --output text)

if [ -n "$EXISTING_PROVIDER" ]; then
  echo -e "${YELLOW}Found existing GitHub OIDC provider: $EXISTING_PROVIDER${NC}"
  OIDC_PROVIDER_ARN="$EXISTING_PROVIDER"
  echo -e "Using existing provider ARN: $OIDC_PROVIDER_ARN"
fi

# Deploy CloudFormation stack
echo -e "Deploying CloudFormation stack $STACK_NAME in region $REGION..."

aws cloudformation deploy \
  --template-file "$CFN_TEMPLATE" \
  --stack-name "$STACK_NAME" \
  --parameter-overrides \
    GitHubOrg="$GITHUB_ORG" \
    RepoName="$REPO_NAME" \
    BranchName="$BRANCH_NAME" \
    OIDCProviderArn="$OIDC_PROVIDER_ARN" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$REGION"

echo -e "${GREEN}Successfully deployed CloudFormation stack $STACK_NAME${NC}"

echo -e "\n${BOLD}Step 2:${NC} Retrieving IAM Role ARN..."

# Get the IAM Role ARN from the CloudFormation stack outputs
ROLE_ARN=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
  --output text)

# Extract the role name from the ARN for informational purposes
ROLE_NAME=$(echo "$ROLE_ARN" | sed 's/.*role\///')
echo -e "${GREEN}Successfully retrieved IAM Role:${NC} $ROLE_NAME"
echo -e "${GREEN}Role ARN:${NC} $ROLE_ARN"

# Verify the role name contains both org and repo name
if [[ "$ROLE_NAME" != *"$GITHUB_ORG"* || "$ROLE_NAME" != *"$REPO_NAME"* ]]; then
  echo -e "${YELLOW}Warning: The role name does not contain both organization and repository name.${NC}"
  echo -e "${YELLOW}This may indicate a problem with the CloudFormation template.${NC}"
  echo -e "${YELLOW}Expected pattern: github-oidc-role-$GITHUB_ORG-$REPO_NAME${NC}"
  echo -e "${YELLOW}Actual role name: $ROLE_NAME${NC}"
fi

echo -e "\n${BOLD}Step 3:${NC} Setting GitHub repository variable AWS_ROLE_TO_ASSUME..."

echo -e "Attempting to set GitHub repository variable for $GITHUB_ORG/$REPO_NAME..."

# Check token permissions with more detailed debugging
echo -e "${YELLOW}Checking GitHub token permissions...${NC}"
TOKEN_INFO=$(curl -s -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user)
TOKEN_PERMISSIONS=$(echo "$TOKEN_INFO" | jq -r '.scopes // []')

# Debug token information
echo -e "${YELLOW}Token info response:${NC}"
echo "$TOKEN_INFO" | jq -r 'del(.plan)' || echo "Failed to parse token info"

# Try a direct API call to test repository access
echo -e "${YELLOW}Testing repository access...${NC}"
REPO_ACCESS=$(curl -s -I -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/repos/$GITHUB_ORG/$REPO_NAME")
echo -e "Repository access status: $(echo "$REPO_ACCESS" | grep -i "HTTP/" | awk '{print $2}')"

# Test variables API access specifically
echo -e "${YELLOW}Testing variables API access...${NC}"
VARS_ACCESS=$(curl -s -I -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/repos/$GITHUB_ORG/$REPO_NAME/actions/variables")
echo -e "Variables API access status: $(echo "$VARS_ACCESS" | grep -i "HTTP/" | awk '{print $2}')"

# Proceed with variable setting if we have access
if [[ "$TOKEN_PERMISSIONS" == *"repo"* ]] || [[ "$TOKEN_PERMISSIONS" == *"admin:repo_hook"* ]] || [[ -z "$TOKEN_PERMISSIONS" ]] || [[ "$(echo "$VARS_ACCESS" | grep -i "HTTP/" | awk '{print $2}')" == "200" ]]; then
  # If permissions are not visible or required permissions are present
  echo -e "${YELLOW}Setting GitHub repository variable AWS_ROLE_TO_ASSUME...${NC}"
  
  # Try to update the variable first with more verbose output
  echo -e "${YELLOW}Attempting to update existing variable...${NC}"
  RESPONSE=$(curl -v -X PATCH \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/repos/$GITHUB_ORG/$REPO_NAME/actions/variables/AWS_ROLE_TO_ASSUME" \
    -d "{\"name\":\"AWS_ROLE_TO_ASSUME\",\"value\":\"$ROLE_ARN\"}" 2>&1)
  
  echo -e "${YELLOW}PATCH response:${NC}"
  echo "$RESPONSE"
  
  # If variable doesn't exist, create it with more verbose output
  if [[ "$RESPONSE" == *"Not Found"* || "$RESPONSE" == *"404"* ]]; then
    echo -e "${YELLOW}Variable doesn't exist, creating it...${NC}"
    RESPONSE=$(curl -v -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/$GITHUB_ORG/$REPO_NAME/actions/variables" \
      -d "{\"name\":\"AWS_ROLE_TO_ASSUME\",\"value\":\"$ROLE_ARN\"}" 2>&1)
    
    echo -e "${YELLOW}POST response:${NC}"
    echo "$RESPONSE"
  fi
  
  # Check response for errors
  if [[ "$RESPONSE" == *"message"* && "$RESPONSE" != *"name already exists"* && "$RESPONSE" != *"{}"* ]]; then
    echo -e "${RED}Error: Failed to set GitHub repository variable. Response: $RESPONSE${NC}"
    echo -e "${YELLOW}You will need to manually set the AWS_ROLE_TO_ASSUME variable in GitHub with value: $ROLE_ARN${NC}"
    echo -e "${YELLOW}Go to your repository settings > Secrets and variables > Actions > Variables${NC}"
    echo -e "${YELLOW}Or use this direct link: https://github.com/$GITHUB_ORG/$REPO_NAME/settings/variables/actions${NC}"
    echo -e "${YELLOW}Create a new variable named AWS_ROLE_TO_ASSUME with the value: $ROLE_ARN${NC}"
  else
    # Check if the variable was actually set
    VERIFY_VARIABLE=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/$GITHUB_ORG/$REPO_NAME/actions/variables/AWS_ROLE_TO_ASSUME")
    
    if [[ "$VERIFY_VARIABLE" == *"AWS_ROLE_TO_ASSUME"* ]]; then
      echo -e "${GREEN}Successfully verified GitHub repository variable AWS_ROLE_TO_ASSUME is set to $ROLE_ARN${NC}"
      echo -e "${GREEN}Your GitHub Actions workflow will now use this variable for AWS authentication${NC}"
      VARIABLE_SET=true
    else
      echo -e "${YELLOW}Warning: Could not verify if the variable was set. Please check manually.${NC}"
      echo -e "${YELLOW}You may need to manually set the AWS_ROLE_TO_ASSUME variable in GitHub with value: $ROLE_ARN${NC}"
      echo -e "${YELLOW}Go to your repository settings > Secrets and variables > Actions > Variables${NC}"
      echo -e "${YELLOW}Or use this direct link: https://github.com/$GITHUB_ORG/$REPO_NAME/settings/variables/actions${NC}"
    fi
  fi
else
  echo -e "${RED}Error: Unable to access repository with provided token. Token does not have required permissions.${NC}"
  echo -e "${YELLOW}Your token needs 'repo' or 'admin:repo_hook' scope to set repository variables.${NC}"
  echo -e "${YELLOW}You will need to manually set the AWS_ROLE_TO_ASSUME variable in GitHub with value: $ROLE_ARN${NC}"
  echo -e "${YELLOW}Go to your repository settings > Secrets and variables > Actions > Variables${NC}"
  echo -e "${YELLOW}Or use this direct link: https://github.com/$GITHUB_ORG/$REPO_NAME/settings/variables/actions${NC}"
  echo -e "${YELLOW}Create a new variable named AWS_ROLE_TO_ASSUME with the value: $ROLE_ARN${NC}"
fi

# Function to update an existing IAM role's trust policy
update_trust_policy() {
  local role_name=$1
  local github_org=$2
  local repo_name=$3
  local provider_arn=$4
  
  echo -e "\n${BOLD}Updating trust policy for role:${NC} $role_name"
  echo -e "${YELLOW}GitHub Org:${NC} $github_org"
  echo -e "${YELLOW}Repo Name:${NC} $repo_name"
  
  # Create a temporary file for the updated trust policy
  TEMP_POLICY_FILE=$(mktemp)
  
  # Create an updated trust policy with comprehensive subject patterns
  cat > "$TEMP_POLICY_FILE" << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "$provider_arn"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:${github_org}/${repo_name}:*",
            "repo:${github_org}/${repo_name}:ref:*",
            "repo:${github_org}/${repo_name}:environment:*",
            "repo:${github_org}/${repo_name}:pull_request",
            "repo:${github_org}/${repo_name}:workflow:*",
            "repo:${github_org}/${repo_name}:branch:*"
          ]
        }
      }
    }
  ]
}
EOF
  
  # Save a copy of the trust policy for reference
  cp "$TEMP_POLICY_FILE" "trust-policy.json"
  echo -e "${YELLOW}Saved trust policy to trust-policy.json for reference${NC}"
  
  # Update the trust policy
  aws iam update-assume-role-policy --role-name "$role_name" --policy-document file://"$TEMP_POLICY_FILE" --region "$REGION"
  
  # Clean up temporary file
  rm "$TEMP_POLICY_FILE"
  
  echo -e "${GREEN}Successfully updated trust policy for role: $role_name${NC}"
  echo -e "${GREEN}Trust policy now includes patterns for: ${github_org}/${repo_name}${NC}"
}

# Try alternative method for setting GitHub variables
set_github_variable() {
  local name=$1
  local value=$2
  local org=$3
  local repo=$4
  local token=$5

  echo -e "${YELLOW}Trying alternative method to set GitHub variable $name...${NC}"
  
  # First, check if the variable exists
  local check_result=$(curl -s -H "Authorization: token $token" \
    "https://api.github.com/repos/$org/$repo/actions/variables/$name")
  
  if [[ "$check_result" == *"Not Found"* || "$check_result" == *"Resource not found"* ]]; then
    # Create new variable
    echo -e "${YELLOW}Creating new variable using alternative method...${NC}"
    local create_result=$(curl -s -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: token $token" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/$org/$repo/actions/variables" \
      -d "{\"name\":\"$name\",\"value\":\"$value\"}")
    
    echo -e "${YELLOW}Create result:${NC} $create_result"
    return 0
  else
    # Update existing variable
    echo -e "${YELLOW}Updating existing variable using alternative method...${NC}"
    local update_result=$(curl -s -X PATCH \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: token $token" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/$org/$repo/actions/variables/$name" \
      -d "{\"name\":\"$name\",\"value\":\"$value\"}")
    
    echo -e "${YELLOW}Update result:${NC} $update_result"
    return 0
  fi
}

# Call the alternative method
set_github_variable "AWS_ROLE_TO_ASSUME" "$ROLE_ARN" "$GITHUB_ORG" "$REPO_NAME" "$GITHUB_TOKEN"

# Clean up temporary directory
rm -rf "$TEMP_DIR"

echo -e "\n${BOLD}Step 4:${NC} Updating trust policy with additional subject patterns..."

# Get the role name from the ARN
ROLE_NAME=$(echo "$ROLE_ARN" | sed 's/.*role\///')

# Update the trust policy for the role
update_trust_policy "$ROLE_NAME" "$GITHUB_ORG" "$REPO_NAME" "$OIDC_PROVIDER_ARN"

echo -e "\n${GREEN}OIDC setup completed successfully!${NC}"
echo -e "${GREEN}Your GitHub Actions workflow can now authenticate with AWS using OIDC.${NC}"
echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "1. Commit and push the changes to your GitHub repository"
echo -e "2. Run the GitHub Actions workflow manually to test the OIDC authentication"
echo -e "3. Check the workflow logs for any authentication errors"

# Track if we had any errors
HAD_ERRORS=false
VARIABLE_SET=false

# Check if the role name contains both org and repo name
if [[ "$ROLE_NAME" != *"$GITHUB_ORG"* || "$ROLE_NAME" != *"$REPO_NAME"* ]]; then
  HAD_ERRORS=true
fi

# Check if we were able to set the GitHub variable
if [[ "$VERIFY_VARIABLE" == *"AWS_ROLE_TO_ASSUME"* ]]; then
  VARIABLE_SET=true
fi

# Only show success message if everything completed without errors
if [[ "$HAD_ERRORS" == "false" && "$VARIABLE_SET" == "true" ]]; then
  echo -e "\n${GREEN}${BOLD}✓ OIDC authentication setup complete!${NC}"
  echo -e "\n${BOLD}To use OIDC authentication in your GitHub Actions workflow:${NC}"
  echo -e "1. Add the following permissions to your job:"
  echo -e "   ${YELLOW}permissions:\n     id-token: write   # Required for OIDC\n     contents: read${NC}"
  echo -e "\n2. Configure AWS credentials using the aws-actions/configure-aws-credentials action:"
  echo -e "   ${YELLOW}- name: Configure AWS credentials\n     uses: aws-actions/configure-aws-credentials@v2\n     with:\n       role-to-assume: \${{ vars.AWS_ROLE_TO_ASSUME }}\n       aws-region: $REGION\n       audience: sts.amazonaws.com${NC}"
  echo -e "\n${BOLD}Your GitHub Actions workflows can now securely authenticate with AWS!${NC}"
elif [[ "$VARIABLE_SET" == "true" && "$HAD_ERRORS" == "true" ]]; then
  echo -e "\n${YELLOW}${BOLD}⚠ OIDC authentication setup completed with minor warnings.${NC}"
  echo -e "${YELLOW}The GitHub variable was set successfully, but there were some warnings.${NC}"
  echo -e "\n${BOLD}Your workflow should use:${NC}"
  echo -e "   ${YELLOW}- name: Configure AWS credentials\n     uses: aws-actions/configure-aws-credentials@v2\n     with:\n       role-to-assume: \${{ vars.AWS_ROLE_TO_ASSUME }}\n       aws-region: $REGION\n       audience: sts.amazonaws.com${NC}"
else
  echo -e "\n${YELLOW}${BOLD}⚠ OIDC authentication setup completed with issues.${NC}"
  echo -e "${YELLOW}Please address the issues above before running your GitHub Actions workflow.${NC}"
  echo -e "\n${BOLD}Once issues are resolved, your workflow should use:${NC}"
  echo -e "   ${YELLOW}- name: Configure AWS credentials\n     uses: aws-actions/configure-aws-credentials@v2\n     with:\n       role-to-assume: \${{ vars.AWS_ROLE_TO_ASSUME }}\n       aws-region: $REGION\n       audience: sts.amazonaws.com${NC}"
fi
