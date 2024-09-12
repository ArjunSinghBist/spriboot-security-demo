This is a very basic implementation of Springboot security using JWT token.

Endpoingts:-
/api/v1/auth/register -> Register the user. This is not secured or authenticated as it should be accessible globally.
       JSON Body Temlate:-
       
        {
            "firstName": <first name>,
            "lastName": <last name>,
            "email": <email id>,
            "password": <password>
        }

/api/v1/auth/login -> Login the registered user. Not secured or authenticated as it should be accessible globally.
    JSON Template:-

    {
    "username": <email id>,
    "password": <password>
}

/api/v1/demo -> Static html page which is authenticated for Bearer (JWT) token.
