storage "raft" {
  path    = "/vault/data"
  node_id = "vault-node-1"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}

listener "tcp" {
  address            = "0.0.0.0:18300"
  tls_cert_file      = "/vault/tls/tls.crt"
  tls_key_file       = "/vault/tls/tls.key"
  tls_client_ca_file = "/vault/tls/ca.crt"
}

api_addr      = "https://vault.internal:18300"
cluster_addr  = "https://vault.internal:18301"
disable_mlock = false
