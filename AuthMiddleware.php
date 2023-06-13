<?php
require __DIR__ . '/classes/JwtHandler.php';

class Auth extends JwtHandler
{
    protected $db;
    protected $headers;
    protected $token;

    public function __construct($db, $headers)
    {
        parent::__construct();
        $this->db = $db;
        $this->headers = $headers;
    }

    public function isValid()
    {

        if (array_key_exists('Authorization', $this->headers) && preg_match('/Bearer\s(\S+)/', $this->headers['Authorization'], $matches)) {

            $data = $this->jwtDecodeData($matches[1]);

            if (
                isset($data['data']->user_id) &&
                $user = $this->fetchUser($data['data']->user_id)
            ) :
                http_response_code(200);
                return [
                    "success" => 1,
                    "user" => $user
                ];
            else :
                http_response_code(401);
                return [
                    "success" => 0,
                    "message" => $data['message'],
                ];
            endif;
        } else {
            http_response_code(400);
            return [
                "success" => 0,
                "message" => "Token not found in request"
            ];
        }
    }

    protected function fetchUser($user_id)
    {
        try {
            $fetch_user_by_id = "SELECT `name`,`email` FROM `users` WHERE `id`=:id";
            $query_stmt = $this->db->prepare($fetch_user_by_id);
            $query_stmt->bindValue(':id', $user_id, PDO::PARAM_INT);
            $query_stmt->execute();

            if ($query_stmt->rowCount()) :
                return $query_stmt->fetch(PDO::FETCH_ASSOC);
            else :
                return false;
            endif;
        } catch (PDOException $e) {
            return null;
        }
    }
}