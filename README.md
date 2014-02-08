HTTP_Request2_Hawk
==================

[Hawk](https://github.com/hueniverse/hawk) authenticated requests with the [HTTP_Request2](https://github.com/pear/HTTP_Request2) package from PEAR.

This class is built as an [Observer](http://pear.php.net/manual/en/package.http.http-request2.observers.php) for HTTP_Request2 that modifies the requests on the **connect** event by adding the Authorization header.

On the **receivedHeaders** event, the Observer also authentifies the Server-Authorization header in the response and makes the result available in the Observer itself for later use.

[Hawk](https://github.com/hueniverse/hawk) is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

Usage example
-------------

```php
require_once 'HTTP/Request2/Observer/Hawk.php';

// Create the request object
$request = new HTTP_Request2('http://example.com/api/test');

// Initialize and attach the Hawk observer
$hawk = new HTTP_Request2_Observer_Hawk('id', 'key', 'sha1');
$request->attach($hawk);

// Perform the request with Hawk Server-Authorization header
$request->send();

// Check if server response is authentified
if ($hawk->isAuthentic()) {
    echo "Server response is authentified";
}

```

