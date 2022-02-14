#Generate password
resource "random_password" "passwords" {
  count   = 1
  length  = 20
  special = true
}
data "yandex_compute_image" "default" {
  family = var.image_family
} 


data "template_file" "default" {
  template = file("ps-init/adds/init.ps1")
  vars = {
    admin_pass = var.admin_pass # random_password.passwords[0].result
  }
}

#Create AD VM
 
resource "yandex_compute_instance" "adds" {
  name     = var.adds_name
  hostname = var.adds_name
  zone     = var.zone

  resources {
    cores  = var.cores
    memory = var.memory
  }

  boot_disk {
    initialize_params {
      image_id = var.image_id
      size     = var.disk_size
      type     = var.disk_type
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.addssubnet[0].id
    nat       = var.nat
  }

  metadata = {
    user-data = data.template_file.default.rendered
  }

  timeouts {
    create = var.timeout_create
    delete = var.timeout_delete
  }
}

# Create Workstation
data "template_file" "ws" {
  depends_on = [
    yandex_compute_instance.adds
  ]
  template = file("ps-init/ws/init.ps1")
  vars = {
    admin_pass = var.admin_pass # random_password.passwords[0].result
    adds_ip = yandex_compute_instance.adds.network_interface.0.ip_address
  }
}

resource "yandex_compute_instance" "ws" {
  depends_on = [
    yandex_compute_instance.adds
  ]
  name     = var.ws_name
  hostname = var.ws_name
  zone     = var.zone

  resources {
    cores  = var.cores
    memory = var.memory
  }

  boot_disk {
    initialize_params {
      image_id = var.image_id
      size     = var.disk_size
      type     = var.disk_type
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.addssubnet[0].id
    nat       = var.nat
  }

  metadata = {
    user-data = data.template_file.ws.rendered
  }

  timeouts {
    create = var.timeout_create
    delete = var.timeout_delete
  }
}

output "adds_name" {
  value = yandex_compute_instance.adds.name
}

output "adds_address" {
  value = yandex_compute_instance.adds.network_interface.0.nat_ip_address
}

output "ws_name" {
  value = yandex_compute_instance.ws.name
}

output "ws_address" {
  value = yandex_compute_instance.ws.network_interface.0.nat_ip_address
}

output "admin_password" {
  value = random_password.passwords[0].result
  sensitive = true
}


