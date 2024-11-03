/*provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}

variable "tags" {
  type = list
  default = ["firstec2","secondec2"]
}

variable "ami" {
  type = map
  default = {
    "us-east-1" = "ami-08a0d1e16fc3f61ea"
    "us-west-2" = "ami-0b20a6f09484773af"
    "ap-south-1" = "ami-0e1d06225679bc1c5"
  }
}


resource "aws_instance" "app-dev" {
   ami = lookup(var.ami,var.region)
   instance_type = "t2.micro"
   count = length(var.tags)

   tags = {
     Name = element(var.tags,count.index)
     CreationDate = formatdate("DD MMM YYYY hh:mm ZZZ",timestamp())
   }
}
*/


























/*
resource "aws_iam_user" "this" {
  name = "demo-kplabs-user"
}

resource "aws_iam_user_policy" "lb_ro" {
  name = "demo-user-policy"
  user = aws_iam_user.this.name

  policy = file("./file.txt")
}
*/


/*
resource "aws_instance" "test_server" {

  ami = "ami-0f3abb15f0395eda8"
  instance_type = "t2.micro"
  //vpc_security_group_ids = [aws_security_group.allow_tls.id]
  //subnet_id =  aws_subnet.shash_subnet.id
  tags = {

    Name = "Shashkansal"

  }

}
*/
/*
resource "aws_eip" "lb" {
  //instance = aws_instance.web.id
  domain   = "vpc"
}

output "public-ip" {
  value = aws_eip.lb
}

*/

/*
resource "aws_security_group" "terrafrom_firewall" {
  name        = "terraform-firewall"
  description = "Allow TLS inbound traffic and all outbound traffic"
  //vpc_id      = aws_vpc.shash_vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.terrafrom_firewall.id
  cidr_ipv4         = var.vpnip
  from_port         = var.appport    //from_port to to_port basically helps to specify a range of port values.
  ip_protocol       = "tcp"
  to_port           = var.appport
}
*/
/*
resource "aws_vpc_security_group_ingress_rule" "allow_tls_ip" {
  security_group_id = aws_security_group.terrafrom_firewall.id
  cidr_ipv4         = "${aws_eip.lb.public_ip}/32"
  from_port         = 443    //from_port to to_port basically helps to specify a range of port values.
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.terrafrom_firewall.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

*/



/*
resource "aws_vpc" "shash_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "shash_mainvpc"
  }
}

resource "aws_subnet" "shash_subnet" {
  vpc_id            = aws_vpc.shash_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "ca-central-1a"

  tags = {
    Name = "shash_subnet1"
  }
}

resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.shash_vpc.id

  tags = {
    Name = "allow_tls"
  }
}



resource "aws_s3_bucket" "shash-bucket" {
  bucket = "my-shashkans-bucket"

  tags = {
    Name        = "Shashkansal"
  }
}

resource "aws_iam_policy" "shash_policy" {
  name        = "shash_policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Statement": [
        {
            "Action": [
                "ec2:Describe*"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
        

    ],
    "Version": "2012-10-17"
})
}

resource "aws_iam_role" "my_role" {
  name               = "my_shashrole"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "my_attachment" {
  role       = aws_iam_role.my_role.name
  policy_arn = aws_iam_policy.shash_policy.arn
}
*/



