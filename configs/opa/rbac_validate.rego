package cara.rbac.validate

default allow = false

allow {
  input.proposed_verbs <= input.requested_verbs
  input.proposed_resources <= input.requested_resources
}
