<?php

namespace Analogic\ACME;

use \RuntimeException;
use \Psr\Log\LoggerInterface;

class Lescript
{
    public $ca = 'https://acme-v02.api.letsencrypt.org';
    public $countryCode = 'CZ';
    public $state = "Czech Republic";
    public $challenge = 'http-01'; // http-01 challenge only by default
    public $contact = array(); // optional

    private $certificatesDir;
    private $webRootDir;
    private $dnsProvider;
    private $dnsCredentials;

    /** @var LoggerInterface */
    private $logger;
    /** @var ClientInterface */
    private $client;
    private $accountKeyPath;

    private $accountId = '';
    private $urlNewAccount = '';
    private $urlNewNonce = '';
    private $urlNewOrder = '';

    public function __construct($certificatesDir, $webRootDir, $logger = null, ClientInterface $client = null)
    {
        $this->certificatesDir = $certificatesDir;
        $this->webRootDir = $webRootDir;
        $this->logger = $logger;
        $this->client = $client ? $client : new Client($this->ca);
        $this->accountKeyPath = $certificatesDir . '/_account/private.pem';
    }

    public function useDnsChallenge($provider, $credentials)
    {
        $this->challenge = 'dns-01';
        $this->dnsProvider = $provider;
        $this->dnsCredentials = $credentials;
    }

    public function initAccount()
    {
        $this->initCommunication();

        if (!is_file($this->accountKeyPath)) {
            $this->log('Starting new account registration');
            $this->generateKey(dirname($this->accountKeyPath));
            $this->postNewReg();
            $this->log('New account certificate registered');
        } else {
            $this->log('Account already registered. Continuing.');
            $this->getAccountId();
        }

        if (empty($this->accountId)) {
            throw new RuntimeException("We don't have account ID");
        }

        $this->log("Account: " . $this->accountId);
    }

    public function initCommunication()
    {
        $this->log('Getting list of URLs for API');
        $directory = $this->client->get('/directory');
        if (!isset($directory['newNonce']) || !isset($directory['newAccount']) || !isset($directory['newOrder'])) {
            throw new RuntimeException("Missing setup urls");
        }
        $this->urlNewNonce = $directory['newNonce'];
        $this->urlNewAccount = $directory['newAccount'];
        $this->urlNewOrder = $directory['newOrder'];
        $this->log('Requesting new nonce for client communication');
        $this->client->get($this->urlNewNonce);
    }

    public function signDomains(array $domains, $reuseCsr = false)
    {
        $this->log('Starting certificate generation process for domains');
        $privateAccountKey = $this->readPrivateKey($this->accountKeyPath);
        $accountKeyDetails = openssl_pkey_get_details($privateAccountKey);

        $this->log("Requesting challenge for " . join(', ', $domains));
        $response = $this->signedRequest(
            $this->urlNewOrder,
            array("identifiers" => array_map(
                function ($domain) {
                    return array("type" => "dns", "value" => $domain);
                },
                $domains
            ))
        );

        $finalizeUrl = $response['finalize'];

        foreach ($response['authorizations'] as $authz) {
            $response = $this->signedRequest($authz, "");
            $domain = $response['identifier']['value'];
            if (empty($response['challenges'])) {
                throw new RuntimeException("Challenge for $domain is not available. Whole response: " . json_encode($response));
            }

            $self = $this;
            $challenge = array_reduce($response['challenges'], function ($v, $w) use (&$self) {
                return $v ? $v : ($w['type'] == $self->challenge ? $w : false);
            });
            if (!$challenge) throw new RuntimeException("Challenge for $domain is not available. Whole response: " . json_encode($response));

            $this->log("Got challenge token for $domain");

            if ($this->challenge == 'dns-01') {
                $this->log("Handling DNS challenge for $domain");
                $dnsChallenge = new DnsChallenge($this->dnsProvider, $this->dnsCredentials);
                $dnsChallenge->setRecord($domain, $challenge['token'], $privateAccountKey);
                $this->log("Waiting for DNS to propagate");
                sleep(30);

                $allowed_loops = 5;
                $result = null;
                while ($allowed_loops > 0) {
                    $result = $this->signedRequest(
                        $challenge['url'],
                        array("keyAuthorization" => $challenge['token'] . '.' . Base64UrlSafeEncoder::encode(hash('sha256', $challenge['token'] . '.' . Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["n"]) . '.' . Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["e"]), true)))
                    );
                    if (empty($result['status']) || $result['status'] == "invalid") {
                        throw new RuntimeException("Verification ended with error: " . json_encode($result));
                    }
                    if ($result['status'] != "pending") {
                        break;
                    }
                    $this->log("Verification pending, sleeping 1s");
                    sleep(1);
                    $allowed_loops--;
                }
                if ($allowed_loops == 0 && $result['status'] === "pending") {
                    throw new RuntimeException("Verification timed out");
                }
                $this->log("Verification ended with status: ${result['status']}");
            } else {
                $directory = $this->webRootDir . '/.well-known/acme-challenge';
                $tokenPath = $directory . '/' . $challenge['token'];
                if (!file_exists($directory) && !@mkdir($directory, 0755, true)) {
                    throw new RuntimeException("Couldn't create directory to expose challenge: ${tokenPath}");
                }
                $header = array(
                    "e" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["e"]),
                    "kty" => "RSA",
                    "n" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["n"])
                );
                $payload = $challenge['token'] . '.' . Base64UrlSafeEncoder::encode(hash('sha256', json_encode($header), true));
                file_put_contents($tokenPath, $payload);
                chmod($tokenPath, 0644);
                $uri = "http://${domain}/.well-known/acme-challenge/${challenge['token']}";
                $this->log("Token for $domain saved at $tokenPath and should be available at $uri");
                if ($payload !== trim(@file_get_contents($uri))) {
                    throw new RuntimeException("Please check $uri - token not available");
                }
                $this->log("Sending request to challenge");
                $allowed_loops = 5;
                $result = null;
                while ($allowed_loops > 0) {
                    $result = $this->signedRequest(
                        $challenge['url'],
                        array("keyAuthorization" => $payload)
                    );
                    if (empty($result['status']) || $result['status'] == "invalid") {
                        throw new RuntimeException("Verification ended with error: " . json_encode($result));
                    }
                    if ($result['status'] != "pending") {
                        break;
                    }
                    $this->log("Verification pending, sleeping 1s");
                    sleep(1);
                    $allowed_loops--;
                }
                if ($allowed_loops == 0 && $result['status'] === "pending") {
                    throw new RuntimeException("Verification timed out");
                }
                $this->log("Verification ended with status: ${result['status']}");
                @unlink($tokenPath);
            }
        }

        $domainPath = $this->getDomainPath(reset($domains));
        if (!is_dir($domainPath) || !is_file($domainPath . '/private.pem')) {
            $this->generateKey($domainPath);
        }

        $privateDomainKey = $this->readPrivateKey($domainPath . '/private.pem');
        $this->client->getLastLinks();
        $csr = $reuseCsr && is_file($domainPath . "/last.csr") ?
            $this->getCsrContent($domainPath . "/last.csr") :
            $this->generateCSR($privateDomainKey, $domains);

        $finalizeResponse = $this->signedRequest($finalizeUrl, array('csr' => $csr));

        if ($this->client->getLastCode() > 299 || $this->client->getLastCode() < 200) {
            throw new RuntimeException("Invalid response code: " . $this->client->getLastCode() . ", " . json_encode($finalizeResponse));
        }

        $location = $finalizeResponse['certificate'];
        $certificates = array();
        while (1) {
            $this->client->getLastLinks();
            $result = $this->signedRequest($location, "");
            if ($this->client->getLastCode() == 202) {
                $this->log("Certificate generation pending, sleeping 1s");
                sleep(1);
            } else if ($this->client->getLastCode() == 200) {
                $this->log("Got certificate! YAY!");
                $serverCert = $this->parseFirstPemFromBody($result);
                $certificates[] = $serverCert;
                $certificates[] = substr($result, strlen($serverCert));
                break;
            } else {
                throw new RuntimeException("Can't get certificate: HTTP code " . $this->client->getLastCode());
            }
        }
        if (empty($certificates)) throw new RuntimeException('No certificates generated');
        $this->log("Saving fullchain.pem");
        file_put_contents($domainPath . '/fullchain.pem', implode("\n", $certificates));
        $this->log("Saving cert.pem");
        file_put_contents($domainPath . '/cert.pem', array_shift($certificates));
        $this->log("Saving chain.pem");
        file_put_contents($domainPath . "/chain.pem", implode("\n", $certificates));
        $this->log("Done!");
    }

    private function readPrivateKey($path)
    {
        if (($key = openssl_pkey_get_private('file://' . $path)) === FALSE) {
            throw new RuntimeException(openssl_error_string());
        }
        return $key;
    }

    private function parseFirstPemFromBody($body)
    {
        preg_match('~(-----BEGIN.*?END CERTIFICATE-----)~s', $body, $matches);
        return $matches[1];
    }

    private function getDomainPath($domain)
    {
        return $this->certificatesDir . '/' . $domain . '/';
    }

    private function getAccountId()
    {
        return $this->postNewReg();
    }

    private function postNewReg()
    {
        $data = array('termsOfServiceAgreed' => true);
        $this->log('Sending registration to letsencrypt server');
        if ($this->contact) {
            $data['contact'] = $this->contact;
        }
        $response = $this->signedRequest($this->urlNewAccount, $data);
        $lastLocation = $this->client->getLastLocation();
        if (!empty($lastLocation)) {
            $this->accountId = $lastLocation;
        }
        return $response;
    }

    private function generateCSR($privateKey, array $domains)
    {
        $domain = reset($domains);
        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));
        $tmpConf = tmpfile();
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        fwrite($tmpConf,
            'HOME = .
RANDFILE = $ENV::HOME/.rnd
[ req ]
default_bits = 2048
default_keyfile = privkey.pem
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
[ v3_req ]
basicConstraints = CA:FALSE
subjectAltName = ' . $san . '
keyUsage = nonRepudiation, digitalSignature, keyEncipherment');

        $csr = openssl_csr_new(
            array(
                "CN" => $domain,
                "ST" => $this->state,
                "C" => $this->countryCode,
                "O" => "Unknown",
            ),
            $privateKey,
            array(
                "config" => $tmpConfPath,
                "digest_alg" => "sha256"
            )
        );

        if (!$csr) throw new RuntimeException("CSR couldn't be generated! " . openssl_error_string());

        openssl_csr_export($csr, $csr);
        fclose($tmpConf);

        $csrPath = $this->getDomainPath($domain) . "/last.csr";
        file_put_contents($csrPath, $csr);

        return $this->getCsrContent($csrPath);
    }

    private function getCsrContent($csrPath)
    {
        $csr = file_get_contents($csrPath);
        preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);
        return trim(Base64UrlSafeEncoder::encode(base64_decode($matches[1])));
    }

    private function generateKey($outputDirectory)
    {
        $res = openssl_pkey_new(array("private_key_type" => OPENSSL_KEYTYPE_RSA, "private_key_bits" => 4096));
        if (!openssl_pkey_export($res, $privateKey)) {
            throw new RuntimeException("Key export failed!");
        }
        $details = openssl_pkey_get_details($res);
        if (!is_dir($outputDirectory)) @mkdir($outputDirectory, 0700, true);
        if (!is_dir($outputDirectory)) throw new RuntimeException("Cant't create directory $outputDirectory");
        file_put_contents($outputDirectory . '/private.pem', $privateKey);
        file_put_contents($outputDirectory . '/public.pem', $details['key']);
    }

    private function signedRequest($uri, $payload, $nonce = null)
    {
        $privateKey = $this->readPrivateKey($this->accountKeyPath);
        $details = openssl_pkey_get_details($privateKey);
        $protected = array(
            "alg" => "RS256",
            "nonce" => $nonce ? $nonce : $this->client->getLastNonce(),
            "url" => $uri
        );
        if ($this->accountId) {
            $protected["kid"] = $this->accountId;
        } else {
            $protected["jwk"] = array(
                "kty" => "RSA",
                "n" => Base64UrlSafeEncoder::encode($details["rsa"]["n"]),
                "e" => Base64UrlSafeEncoder::encode($details["rsa"]["e"]),
            );
        }

        $payload64 = Base64UrlSafeEncoder::encode(empty($payload) ? "" : str_replace('\\/', '/', json_encode($payload)));
        $protected64 = Base64UrlSafeEncoder::encode(json_encode($protected));
        openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, "SHA256");
        $signed64 = Base64UrlSafeEncoder::encode($signed);
        $data = array(
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        );

        $this->log("Sending signed request to $uri");
        return $this->client->post($uri, json_encode($data));
    }

    protected function log($message)
    {
        if ($this->logger) {
            $this->logger->info($message);
        } else {
            echo $message . "\n";
        }
    }
}

class DnsChallenge
{
    private $provider;
    private $credentials;

    public function __construct($provider, $credentials)
    {
        $this->provider = $provider;
        $this->credentials = $credentials;
    }

    public function setRecord($domain, $token, $accountKey)
    {
        if ($this->provider === 'cloudflare') {
            $this->setCloudflareRecord($domain, $token, $accountKey);
        } else {
            throw new RuntimeException("DNS provider {$this->provider} not supported");
        }
    }

    private function setCloudflareRecord($domain, $token, $accountKey)
    {
        $zoneId = $this->getCloudflareZoneId($domain);
        $dnsRecord = [
            'type' => 'TXT',
            'name' => '_acme-challenge.' . $domain,
            'content' => $this->generateDnsContent($token, $accountKey),
            'ttl' => 120
        ];
        $response = $this->cloudflareApiRequest("zones/{$zoneId}/dns_records", 'POST', $dnsRecord);
        if (!isset($response['success']) || !$response['success']) {
            throw new RuntimeException("Failed to create DNS record: " . json_encode($response));
        }
    }

    private function getCloudflareZoneId($domain)
    {
        $response = $this->cloudflareApiRequest("zones?name={$domain}");
        if (empty($response['result'])) {
            throw new RuntimeException("Failed to find zone ID for domain {$domain}");
        }
        return $response['result'][0]['id'];
    }

    private function generateDnsContent($token, $accountKey)
    {
        $accountKeyDetails = openssl_pkey_get_details($accountKey);
        $header = [
            "e" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["e"]),
            "kty" => "RSA",
            "n" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["n"])
        ];
        return $token . '.' . Base64UrlSafeEncoder::encode(hash('sha256', json_encode($header), true));
    }

    private function cloudflareApiRequest($endpoint, $method = 'GET', $data = null)
    {
        $url = 'https://api.cloudflare.com/client/v4/' . $endpoint;
        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->credentials['apiKey']
        ];

        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);

        switch ($method) {
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, json_encode($data));
                break;
            case 'GET':
                break;
            default:
                throw new RuntimeException("Unsupported HTTP method {$method}");
        }

        $response = curl_exec($handle);
        if (curl_errno($handle)) {
            throw new RuntimeException('Curl error: ' . curl_error($handle));
        }

        $httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        if ($httpCode >= 400) {
            throw new RuntimeException("Cloudflare API request failed with HTTP code {$httpCode}");
        }

        return json_decode($response, true);
    }
}

interface ClientInterface
{
    public function __construct($base);
    public function post($url, $data);
    public function get($url);
    public function getLastNonce();
    public function getLastLocation();
    public function getLastCode();
    public function getLastLinks();
}

class Client implements ClientInterface
{
    private $lastCode;
    private $lastHeader;
    private $base;

    public function __construct($base)
    {
        $this->base = $base;
    }

    private function curl($method, $url, $data = null)
    {
        $headers = array('Accept: application/json', 'Content-Type: application/jose+json');
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, preg_match('~^http~', $url) ? $url : $this->base . $url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);

        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
        }
        $response = curl_exec($handle);
        if (curl_errno($handle)) {
            throw new RuntimeException('Curl: ' . curl_error($handle));
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);
        $this->lastHeader = $header;
        $this->lastCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        if ($this->lastCode >= 400 && $this->lastCode < 600) {
            throw new RuntimeException($this->lastCode . "\n" . $body);
        }
        $data = json_decode($body, true);
        return $data === null ? $body : $data;
    }

    public function post($url, $data)
    {
        return $this->curl('POST', $url, $data);
    }

    public function get($url)
    {
        return $this->curl('GET', $url);
    }

    public function getLastNonce()
    {
        if (preg_match('~Replay-Nonce: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }
        throw new RuntimeException("We don't have nonce");
    }

    public function getLastLocation()
    {
        if (preg_match('~Location: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }
        return null;
    }

    public function getLastCode()
    {
        return $this->lastCode;
    }

    public function getLastLinks()
    {
        preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastHeader, $matches);
        return $matches[1];
    }
}

class Base64UrlSafeEncoder
{
    public static function encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}
