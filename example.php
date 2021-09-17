<?php 
require_once __DIR__ . '/vendor/autoload.php';

use Dutta\Ovo;
$ovo = new Ovo('<auth_token>', '<device_id>', '<push_notif_id>');

//v2
////////////////////////////////////////////////////////////
//Auth
/*
@ Step 1
*/
echo $ovo->sendOtp('08XXXXXXXXXX');
/*
@ Step 2
*/
echo $ovo->OTPVerify('08XXXXXXXXXX', '<otp_ref_id>', '<otp_code / otp_link_code>');
/*
@ Step 3
*/
echo $ovo->getAuthToken('08XXXXXXXXXX', '<otp_ref_id>', '<otp_token>', '<security_code>');

//Transactions History
echo $ovo->transactionHistoryv2();


//QrisPay
$qrid = '00020101021126710024ID.CO.MANDIRISYARIAH.WWW0118936004510000003993021000000039930303URE51440014ID.CO.QRIS.WWW0215ID20200312314480303URE5204866153033605802ID5923yys Dompet Umat (Infaq)6009PONTIANAK61057812162070703A016304DD8E'; # qrid
$amount_to_pay = 5000; # amount to pay
$ovo_pin = "XXXXXX"; # your ovo pin / security code

$trx_id = json_decode($ovo->generateTrxId($amount_to_pay, 'PAY_TRX_ID'))->trxId; // generate transaction id , PAY_TRX_ID = action mark for billpay and qris pay
$unlock = json_decode($ovo->unlockAndValidateTrxId($amount_to_pay, $trx_id, $ovo_pin)); // unlock and validate transaction id

if($unlock->isAuthorized){ // is unlock authorized
	echo $ovo->QrisPay($amount_to_pay, $trx_id, $qrid);
}



//V1
////////////////////////////////////////////////////////////
//Auth
/*
@ Step 1
*/
echo $ovo->login2FA('<phone number>');
/*
@ Step 2
*/
echo $ovo->login2FAverify('<reff_id>', '<otp_code>', '<phone number>');
/*
@ Step 3
*/
echo $ovo->loginSecurityCode('<security code>', '<phone number>', '<otp_token>');

//Transactions History
echo $ovo->transactionHistory();
