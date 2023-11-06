<?php

namespace Airasne\DiscordAuth\Security;

use Airasne\DiscordAuth\Exceptions\DiscordInvalidStateException;
use Nette\Http\Session;

class DiscordAuth
{
	const BASE_URL = "https://discord.com";
	const SESSION_SECTION = 'discordAuth';

	public function __construct(
		private Session $session,
		private string  $clientId,
		private string  $secretId,
		private string  $scopes,
		private string  $redirectUrl,
		private string  $botToken
	)
	{
	}

	public function getUrl(): string
	{
		$state = $this->getState();
		return 'https://discordapp.com/oauth2/authorize?response_type=code&client_id=' . $this->clientId . '&redirect_uri=' . $this->redirectUrl . '&scope=' . $this->scopes . "&state=" . $state;
	}

	private function getState(): string
	{
		$section = $this->session->getSection(self::SESSION_SECTION);
		$state = bin2hex(openssl_random_pseudo_bytes(12));
		$section->set('state', $state);
		return $state;
	}

	/**
	 * @throws DiscordInvalidStateException
	 */
	public function init(string $code, string $state): void
	{
		$url = self::BASE_URL . "/api/oauth2/token";
		$data = array(
			"client_id" => $this->clientId,
			"client_secret" => $this->secretId,
			"grant_type" => "authorization_code",
			"code" => $code,
			"redirect_uri" => $this->redirectUrl,
		);
		if (!$this->checkState($state)) {
			throw new DiscordInvalidStateException('Invalid state');
		}
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($data));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		// ignore ssl verification
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);

		$response = curl_exec($curl);
		curl_close($curl);
		$results = json_decode($response, true);
		//save result to file
		$this->session->getSection(self::SESSION_SECTION)->set('access_token', $results['access_token']);
	}

	public function getUser(): mixed
	{
		$url = self::BASE_URL . "/api/users/@me";
		$accessToken = $this->session->getSection(self::SESSION_SECTION)->get('access_token');
		$headers = array('Content-Type: application/x-www-form-urlencoded', 'Authorization: Bearer ' . $accessToken);
		return $this->getResponse($url, $headers);
	}

	public function checkState(string $state): bool
	{
		$sessionState = $this->session->getSection(self::SESSION_SECTION)->get('state');
		return $state === $sessionState;
	}

	public function getResponse(string $url, array $headers): mixed
	{
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		$response = curl_exec($curl);
		curl_close($curl);
		$results = json_decode($response, true);
		return $results;
	}
}