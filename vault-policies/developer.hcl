path "secret/data/{{identity.groups.names.dev-team.id}}/*" {
  capabilities = ["create","read","update","delete"]
}
path "secret/metadata/{{identity.groups.names.dev-team.id}}/*" {
  capabilities = ["list"]
}
