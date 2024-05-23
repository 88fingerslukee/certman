<?php
//	License for all code of this FreePBX module can be found in the license file inside the module directory
//	Copyright 2014 Schmooze Com Inc.
//
$request = $_REQUEST;
$certman2 = FreePBX::Certman();
$message = array();
$request['action'] = !empty($request['action']) ? $request['action'] : "";

echo $certman2->myShowPage($request['action']);
