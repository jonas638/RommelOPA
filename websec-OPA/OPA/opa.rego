package barmanagement
default allow := false

roles := roles {
    auth_header := input.request.headers.Authorization
    token := substring(auth_header, count("Bearer "), -1)
    [_, payload, _] := io.jwt.decode(token)
    roles := payload.role
}

age := age {
    auth_header := input.request.headers.Authorization
    token := substring(auth_header, count("Bearer "), -1)
    [_, payload, _] := io.jwt.decode(token)
    age := to_number(payload.age)
}

is_customer {
    roles := roles
    "customer" == roles[_]
}

is_bartender {
    roles := roles
    "bartender" == roles[_]
}

allow {
    input.request.method == "POST"
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Beer"
    age := age
    age >= 16
}

allow {
    input.request.method == "POST"
    input.request.path == "/api/managebar"
    is_bartender
    input.request.body.DrinkName == "Whiskey"
}

allow {
    input.request.method == "POST"
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Fristi"
}

deny {
    input.request.method == "POST"
    input.request.path == "/api/managebar"
    input.request.body.DrinkName == "Whiskey"
    is_customer
}
