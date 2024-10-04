import { Log, UserManager} from "oidc-client-ts";

Log.setLogger(console);
Log.setLevel(Log.INFO);

const url = window.location.origin + "";

export const settings = {
    authority: "https://dev-x8qvmk6whjqsyu5h.us.auth0.com",
    client_id: "SO6WfIQJWEQcUtbp09chIhrZGzFbtJ2a",
    redirect_uri: url + "/callback.html",
    post_logout_redirect_uri: url + "/index.html",
    response_type: "code",
    scope: "openid email roles",

    response_mode: "query",

    filterProtocolClaims: true,
    extraQueryParams: {
        audience: "bar-auth0-api",
    },
    api_bar_uri: "http://localhost:5172/api/bar",
    api_manageBar_uri: "http://localhost:5172/api/managebar"
};

export {
    Log,
    UserManager
};