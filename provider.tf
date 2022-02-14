# ==================================
# Terraform & Provider Configuration
# ==================================

terraform {
  required_providers {
    yandex = {
      source  = "yandex-cloud/yandex"
      version = "0.66.0"
    }
  }
}

provider "yandex" {
  #service_account_key_file = ""
  #token     = "dsds"
  #cloud_id  = "b1g79uqq99m1pgtjr203"
  #folder_id = "b1gsiiuehmj482621btd"
  zone      = "ru-central1-a"
}
