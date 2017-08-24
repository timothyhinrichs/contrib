package istio.authz

# configuration for the Native authz adapter
config = {
    "mappings": [
       {"resources": ["finance"],
        "verbs": ["get", "list"],
        "permission": "finance.read"},
       {"resources": ["IT","SUPPORT"],
        "verbs": ["*"],
        "permission": "IT.access"}],
    "policies": [
        {"permissions": ["finance.read", "IT.access"],
         "members": [
           {"kind": "User",
	    "name": "alice@example.com"},
	   {"kind": "ServiceAccount",
	    "name": "admin@appspot.gserviceaccount.com"}]},
 	{"permissions": ["finance.read"],
         "members": [
           {"kind": "Group",
            "name": "frontend-admins"}]}]}

# computed by request_context constructor
# Alice does a GET on /finance
request1 = {
    "target_namespace": "default",
    "service": "users",
    "resource": "finance",
    "verb": "get",
        "members": [
            {"kind": "ServiceAccount", "name": "alice"},
            {"kind": "Group", "name": "hr"},
            {"kind": "Namespace", "name": "books"},
            {"kind": "User", "name": "alice@example.com"}]}

# Alice does a PUT on finance
request = {
    "target_namespace": "default",
    "service": "users",
    "resource": "finance",
    "verb": "put",
	"members": [
        {"kind": "ServiceAccount", "name": "alice"},
        {"kind": "Group", "name": "hr"},
        {"kind": "Namespace", "name": "books"},
        {"kind": "User", "name": "alice@example.com"}]}

default allow = false
allow {
    user_has_permission(needed_permission, true)
}

# Data must be in JSON (real data--not policy)
# Indexer likes to see entire structure--no intermediate variables or helpers
# Indexer looks for `groundterm = data...[i]...[j]...` (at eval time).
# Indexer produces Ref1 -> Value1 -> {varbinding1, varbinding2, ...}

user_has_permission(x) {
    p = config.policies[_]              # grab a policy
    permitted_member = p.members[_]     # grab a member for this policy
    request_member = request.members[_] # grab a member provided in request
    permitted_member = request_member   # check if the members are equal
    x = p.permissions[_]                # return each of the permissions in this policy
}

# Lookup the permission required for this request
needed_permission = result {
    m = config.mappings[_]
    m_resource = m.resources[_]
    resource_matches(m_resource, request.resource, true)
    m_verb = m.verbs[_]
    verb_matches(m_verb, request.verb, true)
    result = m.permission
}

resource_matches(x, y) {
    lower(x, lowx)
    lower(y, lowy)
    lowx = lowy
}
resource_matches(x, y) {
    x = "*"
}
verb_matches(x, y) {
    lower(x, lowx)
    lower(y, lowy)
    lowx = lowy
}
verb_matches(x, y) {
    x = "*"
}
