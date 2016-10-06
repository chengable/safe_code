<?php

function check_inner_ip($url)
{
	$match_result=preg_match('/^(http|https)?:\/\/.*(\/)?.*$/',$url);
	if (!$match_result)
	{
		echo 'url fomat error';
		return false;
	}
	try
	{
		$url_parse=parse_url($url);
	}
	catch(Exception $e)
	{
		echo 'url fomat error';
		return false;
	}
	$hostname=$url_parse['host'];
	$ip=gethostbyname($hostname);
	$int_ip=ip2long($ip);
	return ip2long('127.0.0.0')>>24 == $int_ip>>24 || ip2long('10.0.0.0')>>24 == $int_ip>>24 || ip2long('172.16.0.0')>>20 == $int_ip>>20 || ip2long('192.168.0.0')>>16 == $int_ip>>16;
}

function safe_request_url($url)
{
	
	if (check_inner_ip($url))
	{
		echo $url.' is inner ip';
	}
	else
	{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		$output = curl_exec($ch);
		$result_info = curl_getinfo($ch);
		if ($result_info['redirect_url'])
		{
			safe_request_url($result_info['redirect_url']);
		}
		curl_close($ch);
		print_r($output);
	}
	
}
$url='http://www.chengable.com/fftest/test.php';
safe_request_url($url);



?>