<?php
// This file is part of JWT authentication plugin for Moodle.
//
// JWT authentication plugin for Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// JWT authentication plugin for Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with jwt authentication plugin for Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This file contains token controller functions for the JWT authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_jwt;

defined('MOODLE_INTERNAL') || die();

class JWT
{
	/**
	 * Decodes a JWT string into a PHP object.
	 *
	 * @param string      $jwt    The JWT
	 * @param bool        $verify Don't skip verification process
	 *
	 * @return object      The JWT's payload as a PHP object
	 * @throws UnexpectedValueException Provided JWT was invalid
	 * @throws DomainException          Algorithm was not provided
	 *
	 * @uses jsonDecode
	 * @uses urlsafeB64Decode
	 */
	public static function decode($jwt, $verify = true)
	{
		global $CFG;
		$config = get_config('auth_jwt');

		$tks = explode('.', $jwt);
		if (count($tks) != 3)
		{
			throw new \UnexpectedValueException("Wrong number of segments in {$jwt}");
		}

		list($headb64, $bodyb64, $cryptob64) = $tks;

		if (null === ($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64))))
		{
			throw new \UnexpectedValueException('Invalid segment encoding');
		}

		if (null === $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64)))
		{
			throw new \UnexpectedValueException('Invalid segment encoding');
		}

		$sig = JWT::urlsafeB64Decode($cryptob64);

		if ($payload->exp < time())
		{
			throw new \Exception("The token provided has expired.");
		}

		if ($verify)
		{
			if (empty($header->alg))
			{
				throw new \DomainException('Empty algorithm');
			}
			if ($sig != JWT::sign("$headb64.$bodyb64", $header->alg))
			{
				throw new \UnexpectedValueException('Signature verification failed');
			}
		}

		return $payload;
	}

	/**
	 * Converts and signs a PHP object or array into a JWT string.
	 *
	 * @param object|array $payload PHP object or array
	 * @param string       $algo    The signing algorithm. Supported
	 *                              algorithms are 'HS256', 'HS384' and 'HS512'
	 *
	 * @return string      A signed JWT
	 * @uses jsonEncode
	 * @uses urlsafeB64Encode
	 */
	public static function encode($payload, $algo = 'HS256')
	{
		global $CFG;
		$config = get_config('auth_jwt');

		$header = array(
			'typ' => 'JWT',
			'alg' => $algo
		);

		$payload['iss'] = $config->issuer;
		$payload['iat'] = time();
		$payload['exp'] = time() + $config->expiry;

		$segments = array();
		$segments[] = JWT::urlsafeB64Encode(JWT::jsonEncode($header));
		$segments[] = JWT::urlsafeB64Encode(JWT::jsonEncode($payload));
		$signing_input = implode('.', $segments);

		$signature = JWT::sign($signing_input, $algo);
		$segments[] = JWT::urlsafeB64Encode($signature);

		return implode('.', $segments);
	}

	/**
	 * Sign a string with a given key and algorithm.
	 *
	 * @param string $msg    The message to sign
	 * @param string $method The signing algorithm. Supported
	 *                       algorithms are 'HS256', 'HS384' and 'HS512'
	 *
	 * @return string          An encrypted message
	 * @throws DomainException Unsupported algorithm was specified
	 */
	private static function sign($msg, $method = 'HS256')
	{
		global $CFG;
		$config = get_config('auth_jwt');

		$methods = array(
			'HS256' => 'sha256',
			'HS384' => 'sha384',
			'HS512' => 'sha512',
		);

		if (empty($methods[$method]))
		{
			throw new \DomainException('Algorithm not supported');
		}

		return hash_hmac($methods[$method], $msg, $config->secret, true);
	}

	/**
	 * Decode a JSON string into a PHP object.
	 *
	 * @param string $input JSON string
	 *
	 * @return object          Object representation of JSON string
	 * @throws DomainException Provided string was invalid JSON
	 */
	private static function jsonDecode($input)
	{
		$obj = json_decode($input);

		if (function_exists('json_last_error') && $errno = json_last_error())
		{
			JWT::_handleJsonError($errno, json_last_error_msg());
		}
		else if ($obj === null && $input !== 'null')
		{
			throw new \DomainException('Null result with non-null input');
		}

		return $obj;
	}

	/**
	 * Encode a PHP object into a JSON string.
	 *
	 * @param object|array $input A PHP object or array
	 *
	 * @return string          JSON representation of the PHP object or array
	 * @throws DomainException Provided object could not be encoded to valid JSON
	 */
	private static function jsonEncode($input)
	{
		$json = json_encode($input);

		if (function_exists('json_last_error') && $errno = json_last_error())
		{
			JWT::_handleJsonError($errno, json_last_error_msg());
		}
		else if ($json === 'null' && $input !== null)
		{
			throw new \DomainException('Null result with non-null input');
		}

		return $json;
	}

	/**
	 * Decode a string with URL-safe Base64.
	 *
	 * @param string $input A Base64 encoded string
	 *
	 * @return string A decoded string
	 */
	private static function urlsafeB64Decode($input)
	{
		$remainder = strlen($input) % 4;

		if ($remainder)
		{
			$padlen = 4 - $remainder;
			$input .= str_repeat('=', $padlen);
		}

		return base64_decode(strtr($input, '-_', '+/'));
	}

	/**
	 * Encode a string with URL-safe Base64.
	 *
	 * @param string $input The string you want encoded
	 *
	 * @return string The base64 encode of what you passed in
	 */
	private static function urlsafeB64Encode($input)
	{
		return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
	}

	/**
	 * Helper method to create a JSON error.
	 *
	 * @param int $errno An error number from json_last_error()
	 *
	 * @return void
	 */
	private static function _handleJsonError($errno, $errmsg)
	{
		$messages = array(
			JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
			JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
			JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
		);

		throw new \DomainException(
			isset($messages[$errno])
				? $messages[$errno]
				: "{$errmsg}: {$errno}"
		);
	}
}
