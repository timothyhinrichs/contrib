package istio.authz


# computed by request_context constructor
# Alice does a GET on /finance
request = {
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
request1 = {
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
    # find the permission for this request
    request.resource = config.mappings[i].resources[_]
    request.verb = config.mappings[i].verbs[_]
    # lookup this permission if the requesting user has that permission
    config.policies[j].permissions[_] = config.mappings[i].permission
    request.members[_] = config.policies[j].members[_]
}

lower_match(x, y) {
    lower(x, lowx)
    lower(y, lowy)
    lowx = lowy
}
lower_match(x, y) {
    x = "*"
}
lower_match(x, y) {
    y = "*"
}
