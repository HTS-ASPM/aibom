# Demo Terraform — declares an AWS Bedrock foundation model so the
# IaC parser produces a provider finding for `aibom demo`.

resource "aws_bedrock_foundation_model" "x" {
  model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
}

resource "pinecone_index" "demo" {
  name      = "aibom-demo"
  dimension = 1536
}
