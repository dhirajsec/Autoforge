resource "aws_security_group" "test" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # triggers check_open_ssh_ingress
  }
}

resource "aws_s3_bucket" "example" {
  bucket = "my-example-bucket"
  acl    = "public-read"         # triggers public access check
  force_destroy = true
}