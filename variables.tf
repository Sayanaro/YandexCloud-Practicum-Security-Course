variable "vpc_name" {
  description = "VPC Name"
  type = string
  default = "adds-network"
}

variable "net_cidr" {
  description = "Subnet structure primitive"
  type = list(object({
    name = string,
    zone = string,
    prefix = string
  }))

  default = [
    { name = "adds-subnet-a", zone = "ru-central1-a", prefix = "10.60.1.0/24" },
    { name = "adds-subnet-b", zone = "ru-central1-b", prefix = "10.61.1.0/24" },
    { name = "adds-subnet-c", zone = "ru-central1-c", prefix = "10.62.1.0/24" },
  ]

  validation {
    condition = length(var.net_cidr) >= 1
    error_message = "At least one Subnet/Zone should be used."
  }
}

variable "zone" {
  type    = string
  default = "ru-central1-a"
}

variable "nat" {
  type    = bool
  default = true
}

variable "image_family" {
  type    = string
  default = "windows-2019-dc-gvlk"
}

variable "image_id" {
  type    = string
  default = "fd8aic46uv4b9nc3pqt7"
}

variable "platform_id" {
  type    = string
  default = "standard-v3"
}

variable "adds_name" {
  type    = string
}

variable "ws_name" {
  type    = string
}

variable "cores" {
  type    = number
  default = 2
}

variable "memory" {
  type    = number
  default = 4
}

variable "disk_size" {
  type    = number
  default = 50
}

variable "disk_type" {
  type    = string
  default = "network-nvme"
}

variable "admin_pass" {
  type    = string
}

variable "timeout_create" {
  default = "10m"
}

variable "timeout_delete" {
  default = "10m"
}

#-----------------------------------------
variable "opencart_image_id" {
  type    = string
  default = "fd80od21rjl4r3enr4sk"
}


