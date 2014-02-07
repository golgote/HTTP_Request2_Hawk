<?php
/**
 * Hawk authenticated HTTP requests
 *
 * @copyright 2014 Bertrand Mansion <mansion@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause BSD 3-Clause License
 */

/**
 * Class representing a HTTP request message
 */
require_once 'HTTP/Request2.php';

/**
 * Hawk authenticated HTTP requests
 *
 * Server has to implement Hawk authentication as well.
 *
 * Example:
 * <code>
 * $request = new HTTP_Request2('http://example.com/api/test', HTTP_Request2::METHOD_POST);
 * $hawk = new HTTP_Request2_Observer_Hawk('id', 'secret', 'sha1', array('app' => '1', 'nonce' => '123456'));
 * $request->attach($hawk);
 * echo $request->send();
 * </code>
 *
 * @category HTTP
 * @package  HTTP_Request2_Hawk
 * @author   Bertrand Mansion <mansion@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause BSD 3-Clause License
 * @link     https://github.com/golgote/HTTP_Request2_Hawk
 * @link     https://github.com/hueniverse/hawk
 */
class HTTP_Request2_Observer_Hawk implements SplObserver
{

    protected $id;
    protected $key;
    protected $algorithm = 'sha1';
    protected $options = array();
    protected $artifacts = array();
    protected $valid = false;
    public $events = array(
        'connect',
        'receivedHeaders'
    );

    /**
     * Constructor.
     *
     */
    public function __construct($id, $key, $algorithm = 'sha1', $options = array())
    {
        $this->id = $id;
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->options = $options;
        $this->valid = false;
    }


    /**
     * Called when the request notifies us of an event.
     *
     * @param HTTP_Request2 $subject The HTTP_Request2 instance
     *
     * @return void
     */
    public function update(SplSubject $subject)
    {
        $event = $subject->getLastEvent();
        if (!in_array($event['name'], $this->events)) {
            return;
        }

        switch ($event['name']) {
        case 'connect':
            $headers = $subject->getHeaders();
            if (!isset($headers['authorization'])) {
                $this->header($subject);
            }
            break;
        case 'receivedHeaders':
            $response = $event['data'];
            $this->authenticate($response);
            break;
        }
    }


    protected function header(HTTP_Request2 $request)
    {
        $credentials = array(
            'id'        => $this->id,
            'key'       => $this->key,
            'algorithm' => $this->algorithm
        );
        $options = $this->options;

        // Calculate signature

        $url = $request->getUrl();
        $timestamp = isset($options['timestamp']) ? $options['timestamp'] : time() + (!empty($options['localtimeOffsetSec']) ? $options['localtimeOffsetSec'] : 0);
        $method = $request->getMethod();
        $query = $url->getQuery();
        $resource = $url->getPath() . ($query !== false ? '?'.$query : '');
        $nonce = (isset($options['nonce']) && strlen($options['nonce']) ? $options['nonce'] : substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 6));
        $port = $url->getPort();

        $artifacts = array(
            'method'    => $method,
            'resource'  => $resource,
            'nonce'     => $nonce,
            'ts'        => $timestamp,
            'host'      => $url->getHost(),
            'port'      => $port !== false ? $port : ($url->getScheme() == 'http' ? '80' : '443'),
            'hash'      => isset($options['hash']) ? $options['hash'] : null,
            'ext'       => isset($options['ext'])  ? $options['ext']  : null,
            'app'       => isset($options['app'])  ? $options['app']  : null,
            'dlg'       => isset($options['dlg'])  ? $options['dlg']  : null,
        );

        // Calculate payload hash

        if (isset($options['payload']) && strlen($options['payload']) && is_null($artifacts['hash'])) {
            $artifacts['hash'] = self::calculatePayloadHash($options['payload'], $credentials['algorithm'], $options['contentType']);
        }

        $this->artifacts = $artifacts;

        $mac = self::calculateHmac('header', $credentials, $artifacts);

        // Construct header

        $header = 'Hawk id="'.$credentials['id'] .'", ts="'.$artifacts['ts'].'", nonce="'.$artifacts['nonce'] . '",';
        if (isset($artifacts['hash'])) {
            $header .= ' hash="'.$artifacts['hash'].'",';
        }
        if (strlen($artifacts['ext'])) {
            $header .= ' ext="'.str_replace(array('\\', '"'), array('\\\\', '\\"'), $artifacts['ext']).'",';
        }
        $header .= ' mac="'.$mac.'"';
        if (!is_null($artifacts['app'])) {
            $header .= ', app="'.$artifacts['app'].'"';
            if (!is_null($artifacts['dlg'])) {
                $header .= ', dlg="'.$artifacts['dlg'].'"';
            }
        }

        // Add header to request

        $request->setHeader('Authorization', $header);
    }

    public static function calculatePayloadHash($payload, $algorithm, $contentType)
    {
        list($contentType) = explode(';', $contentType);
        $contentType = strtolower(trim($contentType));
        $str = "hawk.1.payload\n" . $contentType."\n" . $payload."\n";
        return base64_encode(hash($algorithm, $str, true));
    }

    public static function calculateHmac($type, $credentials, $artifacts)
    {
        $lines = array('hawk.1.'.$type);

        $lines[] = $artifacts['ts'];
        $lines[] = $artifacts['nonce'];
        $lines[] = strtoupper($artifacts['method']);
        $lines[] = $artifacts['resource'];
        $lines[] = $artifacts['host'];
        $lines[] = $artifacts['port'];
        $lines[] = (isset($artifacts['hash']) && strlen($artifacts['hash'])  ? $artifacts['hash'] : '');
        $lines[] = (isset($artifacts['ext']) && strlen($artifacts['ext'])  ? $artifacts['ext'] : '');

        if (isset($artifacts['app']) && strlen($artifacts['app'])) {
            $lines[] = $artifacts['app'];
            $lines[] = (isset($artifacts['dlg']) && strlen($artifacts['dlg'])  ? $artifacts['dlg'] : '');
        }

        $mac = hash_hmac($credentials['algorithm'], implode("\n", $lines)."\n", $credentials['key'], true);
        return base64_encode($mac);
    }

    public static function parseAuthorizationHeader($header, array $keys = null)
    {
        if (strpos($header, 'Hawk') !== 0) {
            return false;
        }

        $attributes = array();
        $header = substr($header, 5);
        foreach (explode(', ', $header) as $part) {
            $equalsPos = strpos($part, '=');
            $key = substr($part, 0, $equalsPos);
            if (is_array($keys) && in_array($key, $keys)) {
                if (isset($attributes[$key])) {
                    // Duplicate attribute
                    return false;
                }
                $value = trim(substr($part, $equalsPos +1), '"');
                if (!preg_match('/^[ \w\!#\$%&\'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/', $value)) {
                    // Bad attribute value
                    return false;
                }
                $attributes[$key] = $value;
            } elseif (!empty($keys)) {
                // Unknown attribute
                return false;
            }
        }

        return $attributes;
    }

    public function authenticate(HTTP_Request2_Response $response)
    {
        $this->valid = false;

        $credentials = array(
            'id'        => $this->id,
            'key'       => $this->key,
            'algorithm' => $this->algorithm
        );

        $artifacts = $this->artifacts;
        $options = $this->options;

        $wwwauth = $response->getHeader('www-authenticate');
        if ($wwwauth) {
            $attributes = self::parseAuthorizationHeader($wwwauth, array('ts', 'tsm', 'error'));
            if (empty($attributes)) {
                $this->valid = false;
                return;
            }
            if (!empty($attributes['ts'])) {
                $tsm = base64_encode(hash_hmac($credentials['algorithm'], "hawk.1.ts\n".$attributes['ts']."\n", $credentials['key'], true));
                if ($tsm !== $attributes['tsm']) {
                    $this->valid = false;
                    return;
                }
            }
        }

        $authorization = $response->getHeader('server-authorization');
        if (empty($authorization) && empty($options['required'])) {
            $this->valid = true;
            return;
        }

        $attributes = self::parseAuthorizationHeader($authorization, array('mac', 'ext', 'hash'));
        if (empty($attributes)) {
            $this->valid = false;
            return;
        }

        $artifacts['hash'] = isset($attributes['hash']) ? $attributes['hash'] : null;
        $artifacts['ext'] = isset($attributes['ext']) ? $attributes['ext'] : null;

        $mac = self::calculateHmac('response', $credentials, $artifacts);
        if ($mac !== $attributes['mac']) {
            $this->valid = false;
            return;
        }

        if (!isset($options['payload'])) {
            $this->valid = true;
            return;
        }

        if (empty($attributes['hash'])) {
            $this->valid = false;
            return;
        }

        $calculatedHash = self::calculatePayloadHash($options['payload'], $credentials['algorithm'], $response->getHeader('content-type'));
        if ($calculatedHash !== $attributes['hash']) {
            $this->valid = true;
            return;
        }
    }

    public function isAuthentic()
    {
        return $this->valid;
    }
}
