<?php

namespace Airasne\DiscordAuth\DI;

use App\Security\DiscordAuth;
use Nette\DI\CompilerExtension;

class DiscordAuthExtension extends CompilerExtension
{
	public function getConfigSchema(): \Nette\Schema\Schema
	{
		return \Nette\Schema\Expect::structure([
			'clientId' => \Nette\Schema\Expect::string()->required(),
			'secretId' => \Nette\Schema\Expect::string()->required(),
			'scopes' => \Nette\Schema\Expect::string()->required(),
			'redirectUrl' => \Nette\Schema\Expect::string()->required(),
			'botToken' => \Nette\Schema\Expect::string()->required(),
		]);
	}

	public function loadConfiguration(): void
	{
		$config = (object)$this->getConfig();
		$builder = $this->getContainerBuilder();

		$builder->addDefinition('discord')->setType(DiscordAuth::class)->setArguments([
			'clientId' => $config->clientId,
			'secretId' => $config->secretId,
			'scopes' => $config->scopes,
			'redirectUrl' => $config->redirectUrl,
			'botToken' => $config->botToken,
		])->setAutowired(true);
	}
}
