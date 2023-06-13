<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: access");
header("Access-Control-Allow-Methods: POST");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require __DIR__.'/classes/Database.php';

function msg($success,$status,$message,$extra = []){
    return array_merge([
        'success' => $success,
        'status' => $status,
        'message' => $message
    ],$extra);
}

$db_connection = new Database();
$conn = $db_connection->dbConnection();

$data = json_decode(file_get_contents("php://input"));
$returnData = [];

if ($_SERVER["REQUEST_METHOD"] != "POST") :

    http_response_code(405);
    $returnData = msg(0, 405, 'Rrquest Method Not Allowed');

elseif(
	!isset($data->email) 
    || !isset($data->token)
    || empty(trim($data->email))
    || empty(trim($data->token))
):
	$fields = ['fields' => ['email','token']];
    http_response_code(400);
    $returnData = msg(0,400,'Please Fill in all Required Fields!',$fields);
else:
	$email = trim($data->email);
    $token = trim($data->token);

    // CHECKING THE EMAIL FORMAT (IF INVALID FORMAT)
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)):
        http_response_code(400);
        $returnData = msg(0,400,'Invalid Email Address!');
    
    // IF PASSWORD IS LESS THAN 8 THE SHOW THE ERROR
    elseif(strlen($token) < 4):
        http_response_code(400);
        $returnData = msg(0,400,'Invalid OTP');

    // THE USER IS ABLE TO PERFORM THE LOGIN ACTION
    else:
        try{
            
            $fetch_user_by_email = "SELECT * FROM `users` WHERE `email`=:email";
            $query_stmt = $conn->prepare($fetch_user_by_email);
            $query_stmt->bindValue(':email', $email,PDO::PARAM_STR);
            $query_stmt->execute();

            // IF THE USER IS FOUNDED BY EMAIL
            if($query_stmt->rowCount()):
                $user_row = $query_stmt->fetch(PDO::FETCH_ASSOC);

                // Find token by email and token
                $fetch_token_by_email_and_token = "SELECT * FROM `otp` WHERE `user_id` = :user_id AND `token` = :token";
                $otp_query_stmt = $conn->prepare($fetch_token_by_email_and_token);
	            $otp_query_stmt->bindValue(':user_id', $user_row['id'], PDO::PARAM_INT);
	            $otp_query_stmt->bindValue(':token', $token, PDO::PARAM_STR);
	            $otp_query_stmt->execute();

	            if($otp_query_stmt->rowCount()):
                	$otp_row = $otp_query_stmt->fetch(PDO::FETCH_ASSOC);

                	// TODO: Check if token expired

                	/////////////////////////////
                	//  Enable User Operation  //
                	/////////////////////////////
                	$enable_user = "UPDATE `users` SET `enabled` = :enabled WHERE `id` = :id";
                	$enable_user_query_stmt = $conn->prepare($enable_user);
		            $enable_user_query_stmt->bindValue(':enabled', 1, PDO::PARAM_INT);
		            $enable_user_query_stmt->bindValue(':id', $user_row['id'], PDO::PARAM_STR);
		            $enable_user_query_stmt->execute();

		            /////////////////////////////
                	//     Update OTP State    //
                	/////////////////////////////
                	$confirmeddAt = time();
		            $update_otp = "UPDATE `otp` SET `confirmed_at` = :confirmed_at WHERE `id` = :id";
                	$update_otp_query_stmt = $conn->prepare($update_otp);
		            $update_otp_query_stmt->bindValue(':confirmed_at', $confirmeddAt, PDO::PARAM_STR);
		            $update_otp_query_stmt->bindValue(':id', $otp_row['id'], PDO::PARAM_STR);
		            $update_otp_query_stmt->execute();

		            // Evrything work fine
		            http_response_code(200);
                    $returnData = [
                        'success' => 1,
                        'message' => 'Action Enabled Successfully! 😁'
                    ];


                // If token does ont exists
                else:
                	http_response_code(400);
                	$returnData = msg(0,400,'Wrong OTP');
                endif;

            // IF THE USER IS NOT FOUNDED BY EMAIL THEN SHOW THE FOLLOWING ERROR
            else:
                http_response_code(400);
                $returnData = msg(0,400,'Invalid Email Address!');
            endif;
        } catch(PDOException $e) {
            http_response_code(500);
            $returnData = msg(0,500,$e->getMessage());
        }
    endif;
endif;

echo json_encode($returnData);