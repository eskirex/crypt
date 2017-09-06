<?php

namespace Eskirex;

/**
 * Eskirex Crypt
 * @package Eskirex\Crypt
 * @author Eskirex <eskirex@gmail.com>
 * @link http://www.eskirex.com
 * @version 1.0
 */
class DataCrypt
{
    /**
     * @var string
     */
    private $secretKey = 'Eskirex';

    /**
     * @desc   Encrypt Data
     *
     * @param  string|array $value
     * @return string
     */
    public function encrypt($value)
    {
        if (!$value) {
            return false;
        }

        $key = substr(sha1(base64_encode($this->secretKey)), 5, 32);
        $value = @serialize($value);
        $value = $this->openssl_encrypt($value, $key);
        $value = $this->mcrypt_encrypt($value, strrev($key));
        $value = $this->safe_b64encode($value);

        return $value;
    }

    /**
     * @desc   Decrypt Data
     *
     * @param  string $value
     * @return string|array
     */
    public function decrypt($value)
    {
        if (!$value) {
            return false;
        }

        $key = substr(sha1(base64_encode($this->secretKey)), 5, 32);
        $value = $this->safe_b64decode($value);
        $value = $this->mcrypt_decrypt($value, strrev($key));
        $value = $this->openssl_decrypt($value, $key);
        $value = @unserialize($value);

        return $value;

    }

    /**
     * @des    Encrypting openSSL
     * @param  string $value
     * @param  string $key
     * @return string
     */
    private function openssl_encrypt($value, $key)
    {
        $nonceSize = openssl_cipher_iv_length('aes-256-ctr');
        $nonce = openssl_random_pseudo_bytes($nonceSize);

        $ciphertext = openssl_encrypt($value, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $nonce);

        return $nonce . $ciphertext;
    }

    /**
     * @des    Decrypting openSSL
     * @param  string $value
     * @param  string $key
     * @return string
     */
    private function openssl_decrypt($value, $key)
    {
        $nonceSize = openssl_cipher_iv_length('aes-256-ctr');
        $nonce = mb_substr($value, 0, $nonceSize, '8bit');
        $ciphertext = mb_substr($value, $nonceSize, null, '8bit');

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $nonce);

        return $plaintext;
    }

    /**
     * @des    Encrypting MCrypt
     * @param  string|array $value
     * @param  string $key
     * @return string
     */
    private function mcrypt_encrypt($value, $key)
    {
        $value = serialize($value);
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
        $key = pack('H*', $key);
        $mac = hash_hmac('sha256', $value, substr(bin2hex($key), -32));
        $passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $value . $mac, MCRYPT_MODE_CBC, $iv);
        $encoded = $this->safe_b64encode($passcrypt) . '|' . $this->safe_b64encode($iv);

        return $encoded;
    }

    /**
     * @des    Decrypting MCrypt
     * @param  string|array $value
     * @param  string $key
     * @return string
     */
    private function mcrypt_decrypt($value, $key)
    {
        $value = explode('|', $value . '|');
        $decoded = $this->safe_b64decode($value[0]);
        $iv = $this->safe_b64decode($value[1]);
        if (strlen($iv) !== mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)) {
            return false;
        }
        $key = pack('H*', $key);
        $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
        $mac = substr($decrypted, -64);
        $decrypted = substr($decrypted, 0, -64);
        $calcmac = hash_hmac('sha256', $decrypted, substr(bin2hex($key), -32));
        if ($calcmac !== $mac) {
            return false;
        }
        $decrypted = unserialize($decrypted);

        return $decrypted;
    }

    /**
     * @des    Encrypting Base64
     * @param  string $value
     * @return string
     */
    private function safe_b64encode($value)
    {
        $data = base64_encode($value);
        $data = str_replace([
            '+',
            '/',
            '=',
        ], [
            '-',
            '_',
            '',
        ], $data);

        return $data;
    }

    /**
     * @des    Decrypting Base64
     * @param  string $value
     * @return string
     */
    private function safe_b64decode($value)
    {
        $data = str_replace([
            '-',
            '_',
        ], [
            '+',
            '/',
        ], $value);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }

        return base64_decode($data);
    }
}