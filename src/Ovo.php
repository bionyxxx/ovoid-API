<?php

namespace Dutta;
/*
@ Unofficial Ovo API PHP Class
@ Author : namdevel
@ Created at 04-03-2020 14:26
@ Last Modified at 18-07-2021 11:44
*/

class Ovo
{
    /*
    @ Device ID (UUIDV4)
    @ Generated from self::generateUUIDV4();
    */
    /*
    @ Push Notification ID (SHA256 Hash)
    @ Generated from self::generateRandomSHA256();
    */
    const api_url = 'https://api.ovo.id';
    const heusc_api = 'https://agw.heusc.id';

    const BASE_API = "https://api.ovo.id";
    const AGW_API = "https://agw.ovo.id";
    const AWS_API = "https://api.cp1.ovo.id";

    const os = "iOS";
    const app_versionv2 = "3.43.0";
    const client_id = "ovo_ios";
    const user_agentv2 = "OVO/17767 CFNetwork/1220.1 Darwin/20.3.0";

    const os_name = 'iOS';
    const os_version = '14.4.2';
    const app_id = 'P72RVSPSF61F72ELYLZI';
    const app_version = '3.37.0';
    const user_agent = 'OVO/16820 CFNetwork/1220.1 Darwin/20.3.0';
    const action_mark = 'OVO Cash';

    private $auth_token, $hmac_hash, $hmac_hash_random;
    public $push_notif_id, $device_id;

    public function __construct($auth_token = null, $device_id = null, $push_notif_id = null)
    {
        if ($device_id and $push_notif_id) {
            $this->device_id = $device_id; // generated from generateUUIDV4();
            $this->push_notif_id = $push_notif_id; // generated from generateRandomSHA256();
        }
        $this->auth_token = $auth_token;
        //$this->auth_token = 'eyJhbGciOiJSUzI1NiJ9.eyJleHBpcnlJbk1pbGxpU2Vjb25kcyI6NjA0ODAwMDAwLCJjcmVhdGVUaW1lIjoxNjMxODQ5ODk0MDI4LCJzZWNyZXQiOiJzS1lIak9ldlcvNnEvdE1Dam5hQ3NJa3AydEMwN3RFL1h5NkEzRkxXZGJvejZaays3cnBKWnJVbW9IN2lTKzJ5VkRpVnJTU3Q4WXNYUlJHcFdYbDJEOW1BODVaZ2Q0TWpmaFM4em55UnpPNlMxSFNxTUtyNHVCeGRzN25paWNhc3RlbVc0b045ekVhL1RJVjRSdzdwZDdvTFFjWFdaeHhwaVVwSkkyTlgzbVkreHUxWEVldEpxS0xabUhYS1BuZXlzWTdxS0tCNFhzTHFJOHN6R0tXbEd2N0xjZ1VIQThPSVc5b1hEU2krK1ZhYjcrZ1NxMlRNc0JwVmJIdEhTSlp1K2h2TE1LdUlReGpNM3RDN3JkQ3NpNTVBYTk1RS84alEvQVkvWmFkL1NsaW1HZ3czWHBqWFZuc00wNTgxR0ZrKzBqaFc2M2xIcmIwZmk4M1dzaHRMY3dScHBzWnU0a05QQmliNnc3WFlpUTA9In0.a8lN3IMm0oyLJIfDthWmcrBVm5LhT329GhMONQwzQXUjlcTTMF63xFovEbeAgeQ1eYp0-CBXuBU72-GftT6mHH-D2sKIKYG3OHbInMqPwHoS4BlBOwBWAVES2I6QWnpIGQzZbhm1-eruMYTuZ7gBv3awYg-gdIH2Ql8dCA-78ydmw_puOPtvLDh9ebHR2H3t2BJvrOg1kKZvKPtMuVmGMdqRFgHRJkprA0zmMC0Ym6iJuGgOvsAbUPNJZAKF4pKNushSviBYKFHAjx3mlIDi_1Kl7NiSq6-VV5RGMxzPEwSf7Xs1Fkz02Zg6ENadh4wEH-SquXmAKH5XQg12gy7Z0g';
    }

    /*
    @ generateUUIDV4
    @ generate random UUIDV4 for device ID
    */
    public static function generateUUIDV4()
    {
        // $data = random_bytes(16);
        // $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        // return strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4)));


        $data    = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return strtoupper(vsprintf("%s%s-%s-%s-%s-%s%s%s", str_split(bin2hex($data), 4)));
    }

    /*
    @ generateRandomSHA256
    @ generate random SHA256 hash for push notification ID
    */
    public static function generateRandomSHA256()
    {
        return hash_hmac("sha256", time(), "ovo-apps");
    }

    public static function formatPhone($phoneNumber, $areacode = '+62')
    {
        return substr_replace($phoneNumber, $areacode, 0, 1);
    }


    /*
    @ headers
    @ OVO custom headers
    */
    private function headers()
    {
        $headers = array(
            'content-type: application/json',
            'app-id: ' . self::app_id,
            'app-version: ' . self::app_version,
            'os: ' . self::os_name,
            'user-agent: ' . self::user_agent
        );

        return $headers;
    }

    /*
    @ headers
    @ OVO cutsom headers
    */
    protected function headersv2($bearer = false)
    {
        $headers = array(
            'content-type: application/json',
            'accept: */*',
            'app-version: ' . self::app_versionv2,
            'client-id: ' . self::client_id,
            'device-id: ' . $this->device_id,
            'os: ' . self::os,
            'user-agent: ' . self::user_agentv2
        );

        if ($this->auth_token) {
            array_push($headers, 'authorization: ' . $bearer . ' ' . $this->auth_token);
        }

        return $headers;
    }

    /*
    @ Request
    @ Curl http request
    */
    protected function requestv2($url, $post = false, $headers = false)
    {
        $ch = curl_init();

        curl_setopt_array($ch, array(
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0
        ));

        if ($post) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post));
        }

        if ($headers) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }

    /*
    @ parse
    @ parse JSON response
    */
    public function parse($json, $true = true)
    {
        return json_decode($json, $true);
    }

    /*
    @ commander API headers
    @ OVO Commander cutsom headers
    */
    protected function commander_headers()
    {
        $headers = array(
            'accept: application/json, text/plain, */*',
            'app-id: webview-pointexpiry',
            'client-id: ' . self::client_id,
            'accept-language: id',
            'service: police',
            'origin: https://webview.ovo.id',
            'user-agent: ' . self::user_agent,
            'referer: https://webview.ovo.id/pointexpiry?version=3.43.0'
        );

        if ($this->auth_token) {
            array_push($headers, 'authorization: Bearer ' . $this->auth_token);
        }

        if ($this->hmac_hash) {
            array_push($headers, 'hmac: ' . $this->hmac_hash);
        }

        if ($this->hmac_hash_random) {
            array_push($headers, 'random: ' . $this->hmac_hash_random);
        }

        return $headers;
    }

    /*
    @ hashPassword
    @ param (string phone_number, string otp_ref_id, string security_code)
    @ return base64_encoded string
    */
    protected function hashPassword($phone_number, $otp_ref_id, $security_code)
    {
        $rsa_key = $this->parse($this->getPublicKeys(), true)['data']['keys'][0]['key'];
        $data = join("|", array(
            'LOGIN',
            $security_code,
            time(),
            $this->device_id,
            $phone_number,
            $this->device_id,
            $otp_ref_id
        ));
        openssl_public_encrypt($data, $output, $rsa_key);
        return base64_encode($output);
    }

    /*
    @ getPublicKeys
    @ AGW ENDPOINT GET("/v3/user/public_keys")
    */
    public function getPublicKeys()
    {
        return $this->requestv2(self::AGW_API . '/v3/user/public_keys', false, $this->headersv2());
    }

    /*
    @ sendOtp
    @ param (string phone_number)
    @ AGW ENDPOINT POST("/v3/user/accounts/otp")
    */
    public function sendOtp($phone_number)
    {
        $field = array(
            'msisdn' => self::formatPhone($phone_number),
            'device_id' => $this->device_id,
            'otp' => array(
                'locale' => 'EN',
                'sms_hash' => 'abc'
            ),
            'channel_code' => 'ovo_ios'
        );

        return $this->requestv2(self::AGW_API . '/v3/user/accounts/otp', $field, $this->headersv2());
    }

    /*
    @ OTPVerify
    @ param (string phone_number, string otp_ref_id, string otp_code)
    @ AGW ENDPOINT POST("/v3/user/accounts/otp/validation")
    */
    public function OTPVerify($phone_number, $otp_ref_id, $otp_code)
    {
        $field = array(
            'channel_code' => 'ovo_ios',
            'otp' => array(
                'otp_ref_id' => $otp_ref_id,
                'otp' => $otp_code,
                'type' => 'LOGIN'
            ),
            'msisdn' => self::formatPhone($phone_number),
            'device_id' => $this->device_id
        );

        return $this->requestv2(self::AGW_API . '/v3/user/accounts/otp/validation', $field, $this->headersv2());
    }

    /*
    @ getAuthToken
    @ param (string phone_number, string otp_ref_id, string otp_token, string security_code)
    @ AGW ENDPOINT POST("/v3/user/accounts/login")
    */
    public function getAuthToken($phone_number, $otp_ref_id, $otp_token, $security_code)
    {
        $field = array(
            'msisdn' => self::formatPhone($phone_number),
            'device_id' => $this->device_id,
            'push_notification_id' => $this->push_notif_id,
            'credentials' => array(
                'otp_token' => $otp_token,
                'password' => array(
                    'value' => $this->hashPassword(self::formatPhone($phone_number), $otp_ref_id, $security_code),
                    'format' => 'rsa'
                )
            ),
            'channel_code' => 'ovo_ios'
        );

        return $this->requestv2(self::AGW_API . '/v3/user/accounts/login', $field, $this->headersv2());
    }

    /*
    @ transactionHistory
    @ param (int page, int limit)
    @ AGW ENDPOINT GET("/payment/orders/v1/list")
    */
    public function transactionHistoryv2($page = 1, $limit = 10)
    {
        return $this->requestv2(self::AGW_API . "/payment/orders/v1/list?limit=$limit&page=$page", false, $this->headersv2('Bearer'));
    }

    /*
    @ getTransactionDetails
    @ param (string merchant_id. string merchant_invoice)
    @ BASE ENDPOINT GET("/wallet/transaction/{merchant_id}/{merchant_invoice}")
    */
    public function getTransactionDetails($merchant_id, $merchant_invoice)
    {
        return $this->requestv2(self::BASE_API . '/wallet/transaction/' . $merchant_id . '/' . $merchant_invoice . '', false, $this->headersv2());
    }



    /*
    @ getEmail
    @ return account email detail
    */
    public function getEmail()
    {
        return $this->requestv2(self::AGW_API . '/v3/user/accounts/email', false, $this->headersv2());
    }


    /*
    @ walletInquiry
    @ BASE ENDPOINT GET("/wallet/inquiry")
    */
    public function walletInquiryv2()
    {
        return $this->requestv2(self::BASE_API . '/wallet/inquiry', false, $this->headersv2());
    }


    /*
    @ getFavoriteTransfer
    @ AWS ENDPOINT GET("/user-profiling/favorite-transfer")
    */
    public function getFavoriteTransfer()
    {
        return $this->requestv2(self::AWS_API . '/user-profiling/favorite-transfer', false, $this->headersv2());
    }


    /*
    @ getOvoCash (Ovo Balance)
    @ parse self::walletInquiry()
    */
    public function getOvoCash()
    {
        return $this->parse($this->walletInquiryv2(), false)->data->{'001'}->card_balance;
    }


    /*
    @ getAllNotifications
    @ BASE ENDPOINT GET("/v1.0/notification/status/all")
    */
    public function getAllNotifications()
    {
        return $this->requestv2(self::BASE_API . "/v1.0/notification/status/all", false, $this->headersv2());
    }

    /*
    @ getOvoCashCardNumber (Ovo Cash)
    @ parse self::walletInquiry()
    */
    public function getOvoCashCardNumber()
    {
        return $this->parse($this->walletInquiryv2(), false)->data->{'001'}->card_no;
    }

    /*
    @ getOvoPointsCardNumber (Ovo Points)
    @ parse self::walletInquiry()
    */
    public function getOvoPointsCardNumber()
    {
        return $this->parse($this->walletInquiryv2(), false)->data->{'600'}->card_no;
    }

    /*
    @ getOvoPoints
    @ parse self::walletInquiry()
    */
    public function getOvoPoints()
    {
        return $this->parse($this->walletInquiryv2(), false)->data->{'600'}->card_balance;
    }

    /*
    @ getPointDetails
    @ AGW ENDPOINT GET("/api/v1/get-expired-webview")
    */
    public function getPointDetails()
    {
        $json                   = base64_decode(json_decode($this->getHmac())->encrypted_string);
        $json                   = json_decode($json);
        $this->hmac_hash        = $json->hmac;
        $this->hmac_hash_random = $json->random;
        return $this->requestv2(self::AGW_API . "/api/v1/get-expired-webview", false, $this->commander_headers());
    }

    /*
    @ getHmac
    @ GET("https://commander.ovo.id/api/v1/get-expired-webview")
    */
    protected function getHmac()
    {
        return $this->requestv2("https://commander.ovo.id/api/v1/auth/hmac?type=1&encoded=", false, $this->commander_headers());
    }

    /*
    @ getBillerList (get category or biller data)
    @ AWS ENDPOINT GET("/gpdm/ovo/1/v1/billpay/catalogue/getCategories")
    */
    public function getBillerList()
    {
        return $this->requestv2(self::AWS_API . "/gpdm/ovo/1/v1/billpay/catalogue/getCategories?categoryID=0&level=1", false, $this->headersv2());
    }

    /*
    @ getBillerCategory (get biller by category ID)
	@ param (int category_id)
    @ AWS ENDPOINT GET("/gpdm/ovo/ID/v2/billpay/get-billers")
    */
    public function getBillerCategory($category_id)
    {
        return $this->requestv2(self::AWS_API . "/gpdm/ovo/ID/v2/billpay/get-billers?categoryID={$category_id}", false, $this->headersv2());
    }

    /*
    @ getDenominations
	@ param (int product_id)
    @ AWS ENDPOINT GET("/gpdm/ovo/ID/v1/billpay/get-denominations/{product_id}")
    */
    public function getDenominations($product_id)
    {
        return $this->requestv2(self::AWS_API . "/gpdm/ovo/ID/v1/billpay/get-denominations/{$product_id}", false, $this->headersv2());
    }

    /*
    @ getBankList
    @ BASE ENDPOINT GET("/v1.0/reference/master/ref_bank")
    */
    public function getBankListv2()
    {
        return $this->requestv2(self::BASE_API . "/v1.0/reference/master/ref_bank", false, $this->headersv2());
    }

    /*
    @ getUnreadNotifications
    @ BASE ENDPOINT GET("/v1.0/notification/status/count/UNREAD")
    */
    public function getUnreadNotifications()
    {
        return $this->requestv2(self::BASE_API . "/v1.0/notification/status/count/UNREAD", false, $this->headersv2());
    }

    /*
    @ getInvestment
    @ GET("https://investment.ovo.id/customer")
    */
    public function getInvestmentv2()
    {
        return $this->requestv2("https://investment.ovo.id/customer", false, $this->headersv2());
    }

    /*
    @ billerInquiry
    @ param (string phone_number, string otp_ref_id, string otp_code)
    @ AWS ENDPOINT POST("/gpdm/ovo/ID/v2/billpay/inquiry")
    */
    public function billerInquiry($biller_id, $product_id, $denomination_id, $customer_id)
    {
        $field = array(
            'product_id' => $product_id,
            'biller_id' => $biller_id,
            'customer_number' => $customer_id,
            'denomination_id' => $denomination_id,
            'period' => 0,
            'payment_method' => array(
                '001',
                '600',
                'SPLIT'
            ),
            'customer_id' => $customer_id,
            'phone_number' => $customer_id
        );

        return $this->requestv2(self::AWS_API . '/gpdm/ovo/ID/v2/billpay/inquiry?isFavorite=false', $field, $this->headersv2());
    }

    /*
    @ billerPay
    @ param (string biller_id, string product_id, string order_id, int amount, string customer_id)
    @ AWS ENDPOINT POST("/gpdm/ovo/ID/v1/billpay/pay")
    */
    public function billerPay($biller_id, $product_id, $order_id, $amount, $customer_id)
    {
        $field = array(
            "bundling_request" => array(
                array(
                    "product_id" => $product_id,
                    "biller_id" => $biller_id,
                    "order_id" => $order_id,
                    "customer_id" => $customer_id,
                    "parent_id" => "",
                    "payment" => array(
                        array(
                            "amount" => (int) $amount,
                            "card_type" => "001"
                        ),
                        array(
                            "card_type" => "600",
                            "amount" => 0
                        )
                    )
                )
            ),
            "phone_number" => $customer_id
        );

        return $this->requestv2(self::AWS_API . '/gpdm/ovo/ID/v1/billpay/pay', $field, $this->headersv2());
    }

    /*
    @ isOvo
    @ param (int amount, string phone_number)
    @ BASE ENDPOINT POST("/v1.1/api/auth/customer/isOVO")
    */
    public function isOVOv2($amount, $phone_number)
    {
        $field = array(
            'amount' => $amount,
            'mobile' => $phone_number
        );

        return $this->requestv2(self::BASE_API . '/v1.1/api/auth/customer/isOVO', $field, $this->headersv2());
    }

    /*
    @ generateTrxId
    @ param (int amount, string action_mark)
    @ BASE ENDPOINT POST("/v1.0/api/auth/customer/genTrxId")
    */
    public function generateTrxIdv2($amount, $action_mark = "OVO Cash")
    {
        $field = array(
            'amount' => $amount,
            'actionMark' => $action_mark
        );

        return $this->requestv2(self::BASE_API . '/v1.0/api/auth/customer/genTrxId', $field, $this->headersv2());
    }

    /*
    @ generateSignature
	@ param (int amount, string trx_id)
    @ generate unlockAndValidateTrxId signature
    */
    protected function generateSignaturev2($amount, $trx_id)
    {
        return sha1(join('||', array($trx_id, $amount, self::device_id)));
    }

    /*
    @ unlockAndValidateTrxId
    @ param (int amount, string trx_id, string security_code)
    @ BASE ENDPOINT POST("/v1.0/api/auth/customer/genTrxId")
    */
    public function unlockAndValidateTrxId($amount, $trx_id, $security_code)
    {
        $field = array(
            'trxId' => $trx_id,
            'securityCode' => $security_code,
            'signature' => $this->generateSignature($amount, $trx_id)
        );

        return $this->requestv2(self::BASE_API . '/v1.0/api/auth/customer/unlockAndValidateTrxId', $field, $this->headersv2());
    }

    /*
    @ transferOVO
    @ param (int/string amount, string phone_number, string, trx_id, string message)
    @ BASE ENDPOINT POST("/v1.0/api/customers/transfer")
    */
    public function transferOVO($amount, $phone_number, $trx_id, $message = "")
    {
        $field = array(
            'amount' => $amount,
            'to' => $phone_number,
            'trxId' => $trx_id,
            'message' => $message,
        );

        return $this->requestv2(self::BASE_API . '/v1.0/api/customers/transfer', $field, $this->headersv2());
    }


    /*
    @ transferBankInquiry
    @ param (string bank_code, string bank_number, string amount, string message)
    @ BASE ENDPOINT POST("/transfer/inquiry")
    */
    public function transferBankInquiry($bank_code, $bank_number, $amount, $message = "")
    {
        $field = array(
            'bankCode' => $bank_code,
            'accountNo' => $bank_number,
            'amount' => $amount,
            'message' => $message,
        );

        return $this->requestv2(self::BASE_API . '/transfer/inquiry/', $field, $this->headersv2());
    }

    /*
    @ transferBankDirect
    @ param (string bank_code, string bank_number, string amount, string notes)
    @ BASE ENDPOINT POST("/transfer/direct")
    */
    public function transferBankDirect($bank_code, $bank_number, $bank_name, $bank_account_name, $trx_id, $amount, $notes = "")
    {
        $field = array(
            'bankCode' => $bank_code,
            'accountNo' => self::getOvoCashCardNumber(),
            'amount' => $amount,
            'accountNoDestination' => $bank_number,
            'bankName' => $bank_name,
            'accountName' => $bank_account_name,
            'notes' => $notes,
            'transactionId' => $trx_id
        );

        return $this->requestv2(self::BASE_API . '/transfer/direct', $field, $this->headersv2());
    }

    /*
    @ QrisPay
    @ param (int amount, string trx_id, string qrid)
    @ BASE ENDPOINT POST("/wallet/purchase/qr")
    */
    public function QrisPay($amount, $trx_id, $qrid)
    {
        $field = array(
            'qrPayload' => $qrid,
            'locationInfo' => array(
                'accuracy' => 11.00483309472351,
                'verticalAccuracy' => 3,
                'longitude' => 84.90665207978246,
                'heading' => 11.704396994254495,
                'latitude' => -9.432921591875759,
                'altitude' => 84.28827400936305,
                'speed' => 0.11528167128562927
            ),
            'deviceInfo' => array(
                'deviceBrand' => 'Apple',
                'deviceModel' => 'iPhone',
                'appVersion' => self::app_versionv2,
                'deviceToken' => $this->push_notif_id
            ),
            'paymentDetail' => array(
                array(
                    'amount' => $amount,
                    'id' => '001',
                    'name' => 'OVO Cash'
                )
            ),
            'transactionId' => $trx_id,
            'appsource' => 'OVO-APPS'
        );

        return $this->requestv2(self::BASE_API . '/wallet/purchase/qr?qrid=' . urlencode($qrid), $field, $this->headersv2());
    }

    /*
    @ login2FA
    @ POST("/v3/user/accounts/otp")
    */
    public function login2FA($phoneNumber)
    {
        $field = array(
            'msisdn' => $phoneNumber,
            'device_id' => $this->device_id
        );
        return self::Request(self::heusc_api . "/v3/user/accounts/otp", $field, self::headers());
    }

    /*
    @ login2FAverify
    @ POST("/v3/user/accounts/otp/validation")
    */
    public function login2FAverify($reff_id, $otpCode, $phoneNumber)
    {
        $field = array(
            'msisdn' => $phoneNumber,
            'device_id' => $this->device_id,
            'otp_code' => $otpCode,
            'reff_id' => $reff_id
        );
        return self::Request(self::heusc_api . "/v3/user/accounts/otp/validation", $field, self::headers());
    }

    /*
    @ loginSecurityCode
    @ POST("/v3/user/accounts/login")
    */
    public function loginSecurityCode($securityCode, $phoneNumber, $otp_token)
    {
        $field = array(
            'security_code' => $securityCode,
            'msisdn' => $phoneNumber,
            'device_id' => $this->device_id,
            'otp_token' => $otp_token
        );
        return self::Request(self::heusc_api . "/v3/user/accounts/login", $field, self::headers());
    }

    /*
    @ getNotifications
    @ GET("/v1.0/notification/status/all?limit={limit}")
    */
    public function getNotifications($limit = 5)
    {
        return self::Request(self::api_url . "/v1.0/notification/status/all?limit={$limit}", false, self::headers());
    }

    /*
    @ getAccountNumber
    @ parse self::walletInquiry()
    */
    public function getAccountNumber()
    {
        $json = json_decode(self::walletInquiry());
        return $json->data->{'001'}->card_no;
    }

    /*
    @ getBalance
    @ parse self::walletInquiry()
    */
    public function getBalance()
    {
        $json = json_decode(self::walletInquiry());
        return $json->data->{'001'}->card_balance;
    }

    /*
    @ getPoint
    @ parse self::walletInquiry()
    */
    public function getPoint()
    {
        $json = json_decode(self::walletInquiry());
        return $json->data->{'600'}->card_balance;
    }

    /*
    @ walletInquiry
    @ GET("/wallet/inquiry")
    */
    public function walletInquiry()
    {
        return self::Request(self::api_url . "/wallet/inquiry", false, self::headers());
    }

    /*
    @ transactionHistory
    @ GET("/wallet/v2/transaction?page={page}&limit={limit}")
    */
    public function transactionHistory($page = 1, $limit = 10)
    {
        return self::Request(self::api_url . "/wallet/v2/transaction?page={$page}&limit={$limit}", false, self::headers());
    }

    /*
    @ getBankList
    @ GET("/v1.0/reference/master/ref_bank")
    */
    public function getBankList()
    {
        return self::Request(self::api_url . "/v1.0/reference/master/ref_bank", false, self::headers());
    }

    /*
    @ isOVO
    @ POST("/v1.1/api/auth/customer/isOVO")
    */
    public function isOVO($phoneNumber)
    {
        $field = array(
            'mobile' => $phoneNumber,
            'amount' => 10000
        );
        return self::Request(self::api_url . "/v1.1/api/auth/customer/isOVO", $field, self::headers());
    }

    /*
    @ generateTrxId
    @ POST("/v1.0/api/auth/customer/genTrxId")
    */
    private function generateTrxId($amount)
    {
        $field = array(
            'amount' => $amount,
            'actionMark' => self::action_mark
        );
        return self::Request(self::api_url . "/v1.0/api/auth/customer/genTrxId", $field, self::headers());
    }

    /*
    @ generateSignature
    @ unlockTrxId Signature
    */
    private function generateSignature($amount, $trxId)
    {
        $device = $this->device_id;
        return sha1("{$trxId}||{$amount}||{$device}");
    }

    /*
    @ unlockAndValidateTrxId
    @ POST("/v1.0/api/auth/customer/unlockAndValidateTrxId")
    */
    private function unlockTrxId($amount, $trxId, $securityCode)
    {
        $field = array(
            'trxId' => $trxId,
            'signature' => self::generateSignature($amount, $trxId),
            'securityCode' => $securityCode
        );
        return self::Request(self::api_url . "/v1.0/api/auth/customer/unlockAndValidateTrxId", $field, self::headers());
    }



    /*
    @ tfOVO
    @ POST("/v1.0/api/customers/transfer")
    */
    public function tfOVO($amount, $phoneNumber, $securityCode, $message = '')
    {
        $verify = self::isOVO($phoneNumber);
        if (self::getRes($verify)->fullName) {
            $trxId = self::getRes(self::generateTrxId($amount))->trxId;
            $field = array(
                'amount' => $amount,
                'trxId' => $trxId,
                'to' => $phoneNumber,
                'message' => $message
            );
            $tfOVO = self::Request(self::api_url . "/v1.0/api/customers/transfer", $field, self::headers());
            if (preg_match('/sorry unable to handle your request/', $tfOVO)) {
                $unlock = self::unlockTrxId($amount, $trxId, $securityCode);
                if (isset(self::getRes($unlock)->isAuthorized)) {
                    return self::Request(self::api_url . "/v1.0/api/customers/transfer", $field, self::headers());
                } else {
                    return $unlock;
                }
            } else {
                return $tfOVO;
            }
        } else {
            return $verify;
        }
    }

    /*
    @ tfBankPrepare
    @ POST("/transfer/inquiry/")
    */
    private function tfBankPrepare($bankCode, $bankNumber, $amount, $messages = '')
    {
        $field = array(
            'accountNo' => $bankNumber,
            'bankCode' => $bankCode,
            'messages' => $messages,
            'amount' => $amount
        );
        return self::Request(self::api_url . "/transfer/inquiry/", $field, self::headers());
    }

    /*
    @ tfBankExecute
    @ POST("/transfer/direct")
    */
    private function tfBankExecute($amount, $bankName, $bankCode, $bankAccountNumber, $bankAccountName, $trxId, $notes = '')
    {
        $field = array(
            'bankName' => $bankName,
            'notes' => $notes,
            'transactionId' => $trxId,
            'accountNo' => self::getAccountNumber(),
            'accountName' => $bankAccountName,
            'accountNoDestination' => $bankAccountNumber,
            'bankCode' => $bankCode,
            'amount' => $amount
        );
        return self::Request(self::api_url . "/transfer/direct", $field, self::headers());
    }

    /*
    @ tfBank
    @ call self::tfBankPrepare()
    @ call self::tfBankExecute()
    */
    public function tfBank($bankCode, $bankNumber, $amount, $securityCode, $notes = '')
    {
        $tfBankPrepare = self::tfBankPrepare($bankCode, $bankNumber, $amount);
        $bankInfo = self::getRes($tfBankPrepare);
        if ($bankInfo->accountName) {
            $trxId = self::getRes(self::generateTrxId($amount))->trxId;
            $tfBankExecute = self::tfBankExecute($bankInfo->baseAmount, $bankInfo->bankName, $bankInfo->bankCode, $bankInfo->accountNo, $bankInfo->accountName, $trxId, $notes);
            if (preg_match('/sorry unable to handle your request/', $tfBankExecute)) {
                $unlock = self::unlockTrxId($amount, $trxId, $securityCode);
                if (isset(self::getRes($unlock)->isAuthorized)) {
                    return self::tfBankExecute($bankInfo->baseAmount, $bankInfo->bankName, $bankInfo->bankCode, $bankInfo->accountNo, $bankInfo->accountName, $trxId, $notes);
                } else {
                    return $unlock;
                }
            } else {
                return $tfBankExecute;
            }
        } else {
            return $tfBankPrepare;
        }
    }

    /*
    @ getRes
    @ Decoded JSON response
    */
    private function getRes($json)
    {
        return json_decode($json);
    }


    /*
    @ Request
    @ Curl http request
    */
    private function Request($url, $post = false, $headers = false)
    {
        $ch = curl_init();

        curl_setopt_array($ch, array(
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false
        ));

        if ($post) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post));
        }

        if (!empty($this->auth_token)) {
            array_push($this->headers(), "authorization: " . $this->auth_token);
        }

        if ($headers) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
}