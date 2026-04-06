storage "file" {
  path = "./vault-data"
}

disable_mlock = true

listener "tcp" {
  address     = "127.0.0.1:18300"
  tls_disable = 1
}
