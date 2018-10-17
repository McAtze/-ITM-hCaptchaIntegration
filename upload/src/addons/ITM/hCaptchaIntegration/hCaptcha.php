<?php

namespace ITM\hCaptchaIntegration;

use XF\Captcha\AbstractCaptcha;
use XF\Template\Templater;

class hCaptcha extends AbstractCaptcha
{
	public function __construct(\XF\App $app)
	{
		parent::__construct($app);
		$extraKeys = $app->options()->extraCaptchaKeys;
		if (!empty($extraKeys['hCaptchaSiteKey']) && !empty($extraKeys['hCaptchaSecretKey']))
		{
			$this->siteKey = $extraKeys['hCaptchaSiteKey'];
			$this->secretKey = $extraKeys['hCaptchaSecretKey'];
		}
		if (!empty($extraKeys['hCaptchaWidgetTheme']))
		{
			$this->widgetTheme = $extraKeys['hCaptchaWidgetTheme'];
		}
		if (!empty($extraKeys['hCaptchaWidgetSize']))
		{
			$this->widgetSize = $extraKeys['hCaptchaWidgetSize'];
		}
	}
	
	public function renderInternal(Templater $templater)
	{
		if (!$this->siteKey)
		{
			return '';
		}

		return $templater->renderTemplate('public:itm_captcha_hcaptcha', [
			'siteKey' => $this->siteKey,
			'widgetTheme' => $this->widgetTheme,
			'widgetSize' => $this->widgetSize
		]);
	}

	public function isValid()
	{
		if (!$this->siteKey || !$this->secretKey)
		{
			return true; // if not configured, always pass
		}

		$request = $this->app->request();

		$captchaResponse = $request->filter('h-captcha-response', 'str');
		if (!$captchaResponse)
		{
			return false;
		}

		try
		{
			$client = $this->app->http()->client();

			$response = $client->post('https://hcaptcha.com/siteverify',
				['body' => [
					'secret' => $this->secretKey,
					'response' => $captchaResponse,
					'remoteip' => $request->getIp()
				]
			])->json();

			if (isset($response['success']) && isset($response['hostname']) && $response['hostname'] == $request->getHost())
			{
				return $response['success'];
			}

			return false;
		}
		catch(\GuzzleHttp\Exception\RequestException $e)
		{
			// this is an exception with the underlying request, so let it go through
			\XF::logException($e, false, 'hCAPTCHA connection error: ');
			return true;
		}
	}
}