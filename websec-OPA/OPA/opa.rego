package barmanagement

# Default policy: deny access unless explicitly allowed
default allow := false

# Extract roles from the JWT
roles_from_jwt := roles {
    auth_header := input.request.headers.Authorization
    token := substring(auth_header, count("Bearer "), -1)
    [_, payload, _] := io.jwt.decode(token)
    roles := payload.role
}

# Extract age from the JWT
age_from_jwt := age {
    auth_header := input.request.headers.Authorization
    token := substring(auth_header, count("Bearer "), -1)
    [_, payload, _] := io.jwt.decode(token)
    age := to_number(payload.age)
}

# Check if user has the 'customer' role
is_customer {
    roles := roles_from_jwt
    "customer" == roles[_]
}

# Check if user has the 'bartender' role
is_bartender {
    roles := roles_from_jwt
    "bartender" == roles[_]
}

# Allow beer orders if the user is 16 or older
allow {
    input.request.method == "POST"
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Beer"
    age := age_from_jwt
    age >= 16
}

# Allow bartenders to manage the bar and order whiskey
allow {
    input.request.method == "POST"
    input.request.path == "/api/managebar"
    is_bartender
    input.request.body.DrinkName == "Whiskey"
}

# Always allow ordering of 'Fristi'
allow {
    input.request.method == "POST"
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Fristi"
}

# Deny whiskey orders for customers at managebar
deny {
    input.request.method == "POST"
    input.request.path == "/api/managebar"
    input.request.body.DrinkName == "Whiskey"
    is_customer
}
