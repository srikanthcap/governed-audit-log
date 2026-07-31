# Deploying Governed Audit Log to AWS via Terraform

This configuration provisions a production-grade AWS architecture for the Governed Audit Log:
1. **AWS ECR Repository**: Secure container registry.
2. **AWS RDS PostgreSQL Instance** (`db.t4g.micro`): Persistent database storage.
3. **AWS App Runner Service** (1 vCPU, 2GB Memory): Serves the FastAPI application container securely, with HTTPS.

---

## Prerequisites
1. Install [Terraform](https://developer.hashicorp.com/terraform/downloads) on your local machine.
2. Install the [AWS CLI](https://aws.amazon.com/cli/) and authenticate it with your credentials:
   ```bash
   aws configure
   ```

---

## Deployment Steps

### 1. Initialize and Apply Terraform
1. Navigate to this directory:
   ```bash
   cd terraform
   ```
2. Copy the sample variables:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```
3. Edit `terraform.tfvars` and set your database password.
4. Initialize Terraform:
   ```bash
   terraform init
   ```
5. Apply the configuration:
   ```bash
   terraform apply
   ```
6. Confirm the apply. Once done, Terraform will print outputs:
   - `ecr_repository_url`: The URL of your AWS ECR Registry.
   - `app_runner_url`: The HTTPS URL of your running service.

### 2. Build and Push the Docker Container
Once ECR is provisioned, build and push the container image to deploy the code:
1. Login to ECR from your local shell:
   ```bash
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <YOUR_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com
   ```
2. Build the Docker image from the root directory:
   ```bash
   cd ..
   docker build -t governed-audit-log .
   ```
3. Tag the image:
   ```bash
   docker tag governed-audit-log:latest <ecr_repository_url>:latest
   ```
4. Push to ECR:
   ```bash
   docker push <ecr_repository_url>:latest
   ```

### 3. Deploy
On push, AWS App Runner will automatically pull the container and deploy the app! Open the `app_runner_url` in your browser.
