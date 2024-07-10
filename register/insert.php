<?php
$username = $_POST['username'];
$password = $_POST['password'];
$gender = $_POST['gender'];
$email = $_POST['email'];
$phoneCode = $_POST['phoneCode'];
$phone = $_POST['phone'];

if (!empty($username) && !empty($password) && !empty($gender) && !empty($email) &&
    !empty($phoneCode) && !empty($phone)) {
    
    $host = "localhost";
    $dbUsername = "root";
    $dbPassword = "";
    $dbName = "formdb";

    $conn = new mysqli($host, $dbUsername, $dbPassword, $dbName);

    if ($conn->connect_error) {
        die('Connection Error (' . $conn->connect_error . ')');
    } else {
        $SELECT = "SELECT email FROM register WHERE email = ? LIMIT 1";
        $INSERT = "INSERT INTO register (username, password, gender, email, phoneCode, phone) VALUES (?, ?, ?, ?, ?, ?)";

        $stmt = $conn->prepare($SELECT);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $rnum = $stmt->num_rows;

        if ($rnum == 0) {
            $stmt->close();

            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            $stmt = $conn->prepare($INSERT);
            $stmt->bind_param("ssssii", $username, $hashedPassword, $gender, $email, $phoneCode, $phone);
            $stmt->execute();
            echo "Registration Successful";
        } else {
            echo "Email Already Exists";
        }
        $stmt->close();
        $conn->close();
    }
} else {
    echo "All fields are required.";
    die();
}
?>
