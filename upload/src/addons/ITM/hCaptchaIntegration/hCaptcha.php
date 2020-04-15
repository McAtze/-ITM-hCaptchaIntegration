<?php

namespace ITM\hCaptchaIntegration;

use XF\Captcha\AbstractCaptcha;
use XF\Template\Templater;

class hCaptcha extends AbstractCaptcha
{
	/**
	 * @var null|string
	 */
	protected $siteKey = null;

	/**
	 * @var null|string
	 */
	protected $privateKey = null;

	protected $verifyUrl = 'https://hcaptcha.com/siteverify';

	public function __construct(\XF\App $app)	{
		
		parent::__construct($app);
		$extraKeys = $app->options()->extraCaptchaKeys;

		$this->siteKey = $extraKeys['hCaptchaSiteKey'];
		$this->secretKey = $extraKeys['hCaptchaSecretKey'];

		$this->widgetTheme = $extraKeys['hCaptchaWidgetTheme'];
		$this->widgetSize = $extraKeys['hCaptchaWidgetSize'];
	}

	public function renderInternal(Templater $templater) {

		if (!$this->siteKey || !$this->privateKey) {
			return '';
		}

		$ip = $this->app->request()->getIp();
		$sessionId = md5(uniqid('xfkeycaptcha'));
		$sign = md5($sessionId . $ip . $this->privateKey);
		$sign2 = md5($sessionId . $this->privateKey);

		return $templater->renderTemplate('public:itm_captcha_hcaptcha', [
			'siteKey' => $this->siteKey,
			'sessionId' => $sessionId,
			'sign' => $sign,
			'sign2' => $sign2,
			'widgetTheme' => $this->widgetTheme,
			'widgetSize' => $this->widgetSize
		]);
	}

	public function isValid() {

		if (!$this->siteKey || !$this->secretKey)
		{
			return true; // if not configured, always pass
		}

		$request = $this->app->request();

		$captchaResponse = $request->filter('h-captcha-response', 'str');
		if (!$captchaResponse || !is_string($captchaResponse)) {
			return false;
		}

		$data = [
				'secret' => $this->privateKey,
				'response' => $captchaResponse
		];

		try {
			$client = $this->app->http()->client();

			$response = $client->post($this->verifyUrl, [
					'form_params' => $data
			]);

			$contents = @json_decode($response->getBody()->getContents());

			return (bool)$contents->success;
		}
		catch(\GuzzleHttp\Exception\RequestException $e) {
			// this is an exception with the underlying request, so let it go through
			\XF::logException($e, false, 'hCAPTCHA connection error: ');
			return true;
		}
	}
}
