package barmanagement

import future.keywords

# Allow everything by default for debugging
default allow := false

# Rule to allow requests for specific drink names by customers of certain ages
allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    
    # Check for "Beer" and enforce age limit
    input.request.body.DrinkName == "Beer"
    input.role == "customer"
    to_number(input.age) >= 16  
}

allow if {
    input.request.path == "/api/bar"
    input.request.path == "/api/bar"
    input.request.method == "POST"

    # Check for "Fristi" with no age restriction
    input.request.body.DrinkName == "Fristi"
    input.role == "customer"
}
