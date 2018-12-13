<?php
// 类库名称：微信加密数据解密算法
// +----------------------------------------------------------------------
// | PHP version 5.6+
// +----------------------------------------------------------------------
// | Copyright (c) 2012-2014 http://www.myzy.com.cn, All rights reserved.
// +----------------------------------------------------------------------
// | Author: 阶级娃儿 <262877348@qq.com> 群：304104682
// +----------------------------------------------------------------------
namespace think;
use think\ErrorCode;

class WxBizDataCrypt
{
    private $appid;
	private $session_key;

	/**
	 * 构造函数
	 * @param $session_key string 用户在小程序登录后获取的会话密钥
	 * @param $appid string 小程序的appid
	 */
	public function __construct( $appid, $session_key)
	{
		$this->session_key = $session_key;
		$this->appid = $appid;
	}

	/**
	 * [decryptData 检验数据的真实性，并且获取解密后的明文.]
	 * @param  [type] $encryptedData [加密的用户数据]
	 * @param  [type] $iv            [与用户数据一同返回的初始向量]
	 * @param  [type] &$data         [解密后的原文]
	 */
	public function decryptData( $encryptedData, $iv, &$data )
	{
		if (strlen($this->session_key) != 24) {
			return ErrorCode::$IllegalAesKey;
		}

		$aesKey    = base64_decode($this->session_key);

		if (strlen($iv) != 24) {
			return ErrorCode::$IllegalIv;
		}

		$aesIV     = base64_decode($iv);

		$aesCipher = base64_decode($encryptedData);

		$result    = openssl_decrypt( $aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);

		$dataObj   = json_decode( $result );

		if( $dataObj  == NULL ) {
			return ErrorCode::$IllegalBuffer;
		}

		if( $dataObj->watermark->appid != $this->appid ) {
			return ErrorCode::$IllegalBuffer;
		}

		$data = $result;
		return ErrorCode::$OK;
	}
}