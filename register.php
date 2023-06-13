<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: access");
header("Access-Control-Allow-Methods: POST");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require __DIR__ . '/classes/Database.php';
$db_connection = new Database();
$conn = $db_connection->dbConnection();

function msg($success, $status, $message, $extra = []) {
    return array_merge([
        'success' => $success,
        'status' => $status,
        'message' => $message
    ], $extra);
}

function generateOtp() {
    return rand(1000, 9999);
}

// DATA FORM REQUEST
$data = json_decode(file_get_contents("php://input"));
$returnData = [];

if ($_SERVER["REQUEST_METHOD"] != "POST") :

    http_response_code(405);
    $returnData = msg(0, 405, 'Rrquest Method Not Allowed');

elseif (
    !isset($data->name)
    || !isset($data->email)
    || !isset($data->password)
    || empty(trim($data->name))
    || empty(trim($data->email))
    || empty(trim($data->password))
) :

    $fields = ['fields' => ['name', 'email', 'password']];
    http_response_code(400);
    $returnData = msg(0, 400, 'Please Fill in all Required Fields!', $fields);

// IF THERE ARE NO EMPTY FIELDS THEN-
else :

    $name = trim($data->name);
    $email = trim($data->email);
    $password = trim($data->password);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) :
        http_response_code(400);
        $returnData = msg(0, 400, 'Invalid Email Address!');

    elseif (strlen($password) < 8) :
        http_response_code(400);
        $returnData = msg(0, 400, 'Your password must be at least 8 characters long!');

    elseif (strlen($name) < 3) :
        http_response_code(400);
        $returnData = msg(0, 400, 'Your name must be at least 3 characters long!');

    else :
        try {

            $check_email = "SELECT `email` FROM `users` WHERE `email`=:email";
            $check_email_stmt = $conn->prepare($check_email);
            $check_email_stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $check_email_stmt->execute();

            if ($check_email_stmt->rowCount()) :
                http_response_code(400);
                $returnData = msg(0, 400, 'This E-mail is already in use!');

            else :

                ////////////////////////////////
                //  User Insertion Operation  //
                ////////////////////////////////
                $insert_query = "INSERT INTO `users`(`name`,`email`,`password`) VALUES(:name,:email,:password)";

                $insert_stmt = $conn->prepare($insert_query);

                // DATA BINDING
                $insert_stmt->bindValue(':name', htmlspecialchars(strip_tags($name)), PDO::PARAM_STR);
                $insert_stmt->bindValue(':email', $email, PDO::PARAM_STR);
                $insert_stmt->bindValue(':password', password_hash($password, PASSWORD_DEFAULT), PDO::PARAM_STR);


                $insert_stmt->execute();


                ////////////////////////////////
                //  OTP Insertion Operation   //
                ////////////////////////////////
                $otp_query = "INSERT INTO `otp`(`token`,`created_at`,`expires_at`,`user_id`) VALUES(:token, :created_at, :expires_at, :user_id)";

                $otp_stmt = $conn->prepare($otp_query);

                /*Generate OTP Params*/
                $token = generateOtp();
                $createdAt = time();
                $expiresAt = $createdAt + (30 * 60);

                $fetch_user_id_by_email = "SELECT `id` FROM `users` WHERE `email`=:email";
                $query_stmt = $conn->prepare($fetch_user_id_by_email);
                $query_stmt->bindValue(':email', $email, PDO::PARAM_STR);
                $query_stmt->execute();
                $result = $query_stmt->fetch(PDO::FETCH_ASSOC);
                $userId = $result['id'];

                //DATA BINDING
                $otp_stmt->bindValue(":token", $token);
                $otp_stmt->bindValue(":created_at", $createdAt);
                $otp_stmt->bindValue(":expires_at", $expiresAt);
                $otp_stmt->bindValue(":user_id", $userId);

                $otp_stmt->execute();

                http_response_code(201);
                $returnData = msg(1, 201, 'You have successfully registered.');

            endif;
        } catch (PDOException $e) {
            http_response_code(500);
            $returnData = msg(0, 500, $e->getMessage());
        }
    endif;
endif;

echo json_encode($returnData);
