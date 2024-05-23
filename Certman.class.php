<?php
// vim: set ai ts=4 sw=4 ft=php:
//	License for all code of this FreePBX module can be found in the license file inside the module directory
//	Copyright 2014 Schmooze Com Inc.
//	Copyright 2018 Sangoma Technologies.
namespace FreePBX\modules;

include_once __DIR__."/vendor/autoload.php";

use Composer\CaBundle\CaBundle;
use BMO;
use PDO;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use Exception;
class Certman implements BMO {
	/* Asterisk Defaults */
	private $defaults = array(
		"sip" => array(
			"dtlsenable" => "no",
			"dtlsverify" => "fingerprint",
			"dtlscertfile" => "",
			"dtlscafile" => "",
			"dtlssetup" => "actpass",
			"dtlsrekey" => "0"
		),
		"pjsip" => array(
			"media_encryption" => "dtls",
			"dtls_verify" => "fingerprint",
			"dtls_cert_file" => "",
			"dtls_ca_file" => "",
			"dtls_setup" => "actpass",
			"dtls_rekey" => "0"
		)
	);
	private $message = "";

	public function __construct($freepbx = null) {
		if ($freepbx == null){
			throw new Exception("Not given a FreePBX Object");
		}
		$this->FreePBX = $freepbx;
		$this->db = $freepbx->Database;
		$this->FreePBX->PJSip = $this->FreePBX->Core->getDriver('pjsip');
		$this->PKCS = $this->FreePBX->PKCS;
		$this->PKCS->timeout = 240; //because of piiiiiis
		$this->days_expiration_alert = $this->FreePBX->Config->get("CERT_DAYS_EXPIRATION_ALERT");
	}

	public function setDatabase($pdo){
		$this->db = $pdo;
		return $this;
	}

	public function resetDatabase(){
		$this->db = $this->FreePBX->Database;
	}

	/**
	 * Used to setup the database
	 */
	public function install() {
		$certs = $this->getAllManagedCertificates();
		if(empty($certs)) {
			out(_("No Certificates exist"));

			if(!$this->checkCAexists()) {
				outn(_("Generating default CA..."));
				$hostname = gethostname();
				$hostname = !empty($hostname) ? $hostname : 'localhost';
				$caid = $this->generateCA('ca', $hostname, $hostname);
				out(_("Done!"));
			} else {
				$data = $this->getCA();
				$caid = $data['id'];
			}

			outn(_("Generating default certificate..."));
			$hostname = gethostname();
			$hostname = !empty($hostname) ? $hostname : 'localhost';
			$this->generateSelfSigned($hostname, $hostname, $caid);
			out(_("Done!"));
		}
	}

	/**
	 * Get all certificates that are managed by this module
	 *
	 * @return array
	 */
	public function getAllManagedCertificates() {
		$sql = "SELECT * FROM certman_certs WHERE managed = 1";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$results = $sth->fetchAll(PDO::FETCH_ASSOC);
		return $results;
	}

	public function getCA() {
		$sql = "SELECT * FROM certman_cas";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$results = $sth->fetch(PDO::FETCH_ASSOC);
		return $results;
	}

	public function getAll() {
		$sql = "SELECT * FROM certman_certs";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$results = $sth->fetchAll(PDO::FETCH_ASSOC);
		return $results;
	}

	/**
	 * Validate data before saving it
	 *
	 * @param array $data
	 * @return boolean
	 */
	public function validateData($data) {
		if(empty($data['name'])) {
			throw new Exception(_("Name must be specified"));
		}

		if(empty($data['ca'])) {
			throw new Exception(_("CA must be specified"));
		}

		if(empty($data['country'])) {
			throw new Exception(_("Country must be specified"));
		}

		if(empty($data['state'])) {
			throw new Exception(_("State must be specified"));
		}

		if(empty($data['locality'])) {
			throw new Exception(_("Locality must be specified"));
		}

		if(empty($data['organization'])) {
			throw new Exception(_("Organization must be specified"));
		}

		if(empty($data['email'])) {
			throw new Exception(_("Email must be specified"));
		}

		if(empty($data['keylength'])) {
			throw new Exception(_("Key Length must be specified"));
		}

		if(!in_array($data['keylength'], array(2048, 4096))) {
			throw new Exception(_("Key Length must be 2048 or 4096"));
		}

		return true;
	}

	/**
	 * Add a new certificate
	 *
	 * @param array $data
	 */
	public function add($data) {
		$this->validateData($data);
		$ca = $this->getCA();

		$sql = "INSERT INTO certman_certs (name, ca, country, state, locality, organization, email, keylength, managed) VALUES (:name, :ca, :country, :state, :locality, :organization, :email, :keylength, 1)";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $data['name']);
		$sth->bindParam(':ca', $ca['id']);
		$sth->bindParam(':country', $data['country']);
		$sth->bindParam(':state', $data['state']);
		$sth->bindParam(':locality', $data['locality']);
		$sth->bindParam(':organization', $data['organization']);
		$sth->bindParam(':email', $data['email']);
			$sth->bindParam(':keylength', $data['keylength']);
		$sth->execute();
	}

	/**
	 * Update a certificate
	 *
	 * @param array $data
	 */
	public function update($data) {
		$this->validateData($data);

		$sql = "UPDATE certman_certs SET name = :name, country = :country, state = :state, locality = :locality, organization = :organization, email = :email, keylength = :keylength WHERE id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $data['name']);
		$sth->bindParam(':country', $data['country']);
		$sth->bindParam(':state', $data['state']);
		$sth->bindParam(':locality', $data['locality']);
		$sth->bindParam(':organization', $data['organization']);
		$sth->bindParam(':email', $data['email']);
		$sth->bindParam(':keylength', $data['keylength']);
		$sth->bindParam(':id', $data['id']);
		$sth->execute();
	}

	/**
	 * Delete a certificate
	 *
	 * @param integer $id
	 */
	public function delete($id) {
		$sql = "DELETE FROM certman_certs WHERE id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':id', $id);
		$sth->execute();
	}

	/**
	 * Generate a self signed certificate
	 *
	 * @param string $name
	 * @param string $hostname
	 * @param integer $ca
	 */
	public function generateSelfSigned($name, $hostname, $ca) {
		$sslconfig = $this->generateSSLConfig($name, $hostname, $ca);
		$sslconfig['digest_alg'] = "sha256";
		$sslconfig['x509_extensions'] = "v3_req";
		$sslconfig['req_extensions'] = "v3_req";

		$privkey = openssl_pkey_new(array(
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		));

		$csr = openssl_csr_new($sslconfig, $privkey);
		$sscert = openssl_csr_sign($csr, null, $privkey, 365);

		openssl_x509_export($sscert, $certout);
		openssl_pkey_export($privkey, $pkeyout);
		openssl_csr_export($csr, $csrout);

		$data = array(
			'name' => $name,
			'ca' => $ca,
			'country' => $sslconfig['C'],
			'state' => $sslconfig['ST'],
			'locality' => $sslconfig['L'],
			'organization' => $sslconfig['O'],
			'email' => $sslconfig['emailAddress'],
			'keylength' => 2048
		);

		$this->add($data);

		$sql = "UPDATE certman_certs SET cert = :cert, key = :key, csr = :csr WHERE name = :name AND ca = :ca";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':cert', $certout);
		$sth->bindParam(':key', $pkeyout);
		$sth->bindParam(':csr', $csrout);
		$sth->bindParam(':name', $name);
		$sth->bindParam(':ca', $ca);
		$sth->execute();
	}

	/**
	 * Generate a certificate signing request
	 *
	 * @param string $name
	 * @param string $hostname
	 * @param integer $ca
	 */
	public function generateCSR($name, $hostname, $ca) {
		$sslconfig = $this->generateSSLConfig($name, $hostname, $ca);
		$sslconfig['digest_alg'] = "sha256";
		$sslconfig['x509_extensions'] = "v3_req";
		$sslconfig['req_extensions'] = "v3_req";

		$privkey = openssl_pkey_new(array(
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		));

		$csr = openssl_csr_new($sslconfig, $privkey);

		openssl_pkey_export($privkey, $pkeyout);
		openssl_csr_export($csr, $csrout);

		$sql = "INSERT INTO certman_certs (name, ca, country, state, locality, organization, email, keylength, managed, csr, key) VALUES (:name, :ca, :country, :state, :locality, :organization, :email, 2048, 1, :csr, :key)";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $name);
		$sth->bindParam(':ca', $ca);
		$sth->bindParam(':country', $sslconfig['C']);
		$sth->bindParam(':state', $sslconfig['ST']);
		$sth->bindParam(':locality', $sslconfig['L']);
		$sth->bindParam(':organization', $sslconfig['O']);
		$sth->bindParam(':email', $sslconfig['emailAddress']);
		$sth->bindParam(':csr', $csrout);
		$sth->bindParam(':key', $pkeyout);
		$sth->execute();
	}

	/**
	 * Generate an SSL configuration for a certificate
	 *
	 * @param string $name
	 * @param string $hostname
	 * @param integer $ca
	 * @return array
	 */
	private function generateSSLConfig($name, $hostname, $ca) {
		$data = $this->getCA($ca);

		$config = array(
			'digest_alg' => "sha256",
			'x509_extensions' => "v3_req",
			'req_extensions' => "v3_req",
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
			'encrypt_key' => false,
			'config' => CaBundle::getBundledCaBundlePath(),
			'configargs' => array('commonName' => $hostname),
			'configsections' => array(
				'distinguished_name' => array(
					'C' => $data['country'],
					'ST' => $data['state'],
					'L' => $data['locality'],
					'O' => $data['organization'],
					'emailAddress' => $data['email']
				),
				'v3_req' => array(
					'subjectAltName' => 'DNS:' . $hostname
				)
			)
		);

		return $config;
	}

	/**
	 * Generate a certificate authority
	 *
	 * @param string $name
	 * @param string $hostname
	 * @param string $country
	 * @param string $state
	 * @param string $locality
	 * @param string $organization
	 * @param string $email
	 * @param integer $keylength
	 */
	public function generateCA($name, $hostname, $country, $state, $locality, $organization, $email, $keylength) {
		$sslconfig = $this->generateSSLConfig($name, $hostname, $keylength);
		$sslconfig['digest_alg'] = "sha256";
		$sslconfig['x509_extensions'] = "v3_ca";
		$sslconfig['req_extensions'] = "v3_ca";

		$privkey = openssl_pkey_new(array(
			'private_key_bits' => $keylength,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		));

		$csr = openssl_csr_new($sslconfig, $privkey);
		$cacert = openssl_csr_sign($csr, null, $privkey, 365);

		openssl_x509_export($cacert, $certout);
		openssl_pkey_export($privkey, $pkeyout);
		openssl_csr_export($csr, $csrout);

		$sql = "INSERT INTO certman_cas (name, country, state, locality, organization, email, keylength, cert, key, csr) VALUES (:name, :country, :state, :locality, :organization, :email, :keylength, :cert, :key, :csr)";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $name);
		$sth->bindParam(':country', $country);
		$sth->bindParam(':state', $state);
		$sth->bindParam(':locality', $locality);
		$sth->bindParam(':organization', $organization);
		$sth->bindParam(':email', $email);
		$sth->bindParam(':keylength', $keylength);
		$sth->bindParam(':cert', $certout);
		$sth->bindParam(':key', $pkeyout);
		$sth->bindParam(':csr', $csrout);
		$sth->execute();
	}

	/**
	 * Get all certificates signed by a specific CA
	 *
	 * @param integer $ca
	 * @return array
	 */
	public function getAllCertificatesByCA($ca) {
		$sql = "SELECT * FROM certman_certs WHERE ca = :ca";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':ca', $ca);
		$sth->execute();
		$results = $sth->fetchAll(PDO::FETCH_ASSOC);
		return $results;
	}

	/**
	 * Renew a certificate
	 *
	 * @param integer $id
	 */
	public function renew($id) {
		$cert = $this->getCertificate($id);
		$this->generateCSR($cert['name'], $cert['hostname'], $cert['ca']);
	}

	/**
	 * Get a certificate
	 *
	 * @param integer $id
	 * @return array
	 */
	public function getCertificate($id) {
		$sql = "SELECT * FROM certman_certs WHERE id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':id', $id);
		$sth->execute();
		$result = $sth->fetch(PDO::FETCH_ASSOC);
		return $result;
	}

	/**
	 * Update a certificate's information
	 *
	 * @param array $data
	 */
	public function updateCertificate($data) {
		$sql = "UPDATE certman_certs SET name = :name, country = :country, state = :state, locality = :locality, organization = :organization, email = :email, keylength = :keylength, managed = :managed WHERE id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $data['name']);
		$sth->bindParam(':country', $data['country']);
		$sth->bindParam(':state', $data['state']);
		$sth->bindParam(':locality', $data['locality']);
		$sth->bindParam(':organization', $data['organization']);
		$sth->bindParam(':email', $data['email']);
		$sth->bindParam(':keylength', $data['keylength']);
		$sth->bindParam(':managed', $data['managed']);
		$sth->bindParam(':id', $data['id']);
		$sth->execute();
	}

	/**
	 * Get the issuer's certificate authority
	 *
	 * @param string $issuer
	 * @return array
	 */
	public function getIssuerCA($issuer) {
		$sql = "SELECT * FROM certman_cas WHERE name = :name";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $issuer);
		$sth->execute();
		$result = $sth->fetch(PDO::FETCH_ASSOC);
		return $result;
	}

	/**
	 * Check if a certificate exists
	 *
	 * @param string $name
	 * @return boolean
	 */
	public function certificateExists($name) {
		$sql = "SELECT COUNT(*) FROM certman_certs WHERE name = :name";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(':name', $name);
		$sth->execute();
		$count = $sth->fetchColumn();
		return $count > 0;
	}

	/**
	 * Check if a certificate authority exists
	 *
	 * @return boolean
	 */
	public function checkCAexists() {
		$sql = "SELECT COUNT(*) FROM certman_cas";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$count = $sth->fetchColumn();
		return $count > 0;
	}

	/**
	 * Enable firewall rules for Let's Encrypt
	 */
	public function enableFirewallLeRules() {
		$api = $this->getFirewallAPI();
		$module_info = module_getinfo('firewall', MODULE_STATUS_ENABLED);

		if ($module_info && !empty($api)) {
			$rules = array(
				'le_tls' => array(
					'rules' => array(
						'default' => array(
							'dest' => array(
								'host' => '0.0.0.0',
								'port' => array(
									'80/tcp'
								)
							)
						)
					)
				)
			);
			$api->addRules('Lets Encrypt', $rules);
		}
	}

	/**
	 * Disable firewall rules for Let's Encrypt
	 */
	public function disableFirewallLeRules() {
		$api = $this->getFirewallAPI();
		$module_info = module_getinfo('firewall', MODULE_STATUS_ENABLED);

		if ($module_info && !empty($api)) {
			$api->removeRules('Lets Encrypt');
		}
	}

	private function getFirewallAPI() {
		if (class_exists('FirewallAPI')) {
			return new \FreePBX\modules\FirewallAPI();
		}
		return false;
	}

    /* Request Let's Encrypt certificate */
    public function requestLetsEncryptCertificate($hostname, $email, $challengeType, $dnsProvider = null, $dnsCredentials = null) {
        // Define paths
        $location = "/etc/asterisk/keys/$hostname";
        $webroot = "/var/www/html";

        // Logger
        $logger = new \Analogic\ACME\Logger();

        // Initialize Lescript with location and webroot
        $le = new \Analogic\ACME\Lescript($location, $webroot, $logger);

        // Set the CA to staging if required
        if ($this->FreePBX->Config->get("CERT_STAGING")) {
            $le->ca = 'https://acme-staging.api.letsencrypt.org';
        }

        // Set country code and state
        $le->countryCode = 'US';
        $le->state = 'California';

        // Set email contact
        if (!empty($email)) {
            $le->contact = array("mailto:" . $email);
        }

        // Use DNS challenge if specified
        if ($challengeType === 'dns') {
            $le->useDnsChallenge($dnsProvider, $dnsCredentials);
        } else {
            $le->useHttpChallenge();
        }

        // Initialize account and sign domains
        $le->initAccount();
        $le->signDomains([$hostname]);
    }
}
