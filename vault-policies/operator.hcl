path "sys/health" { capabilities = ["read"] }
path "sys/seal" { capabilities = ["update"] }
path "sys/audit" { capabilities = ["read","update","sudo"] }
path "sys/policies/acl/*" { capabilities = ["read","list"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
