HTTP_Request2_Hawk
==================

Hawk authenticated requests with the HTTP_Request2 package from PEAR.

Hawk is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

This class is built as an Observer for HTTP_Request2 that modifies the requests on connect by adding the Server-Authorization header.

Once the request is completed, it also authentifies the server response and makes the result of the authentication available in the Observer itself for later use.

Examples and documentation coming soon...
