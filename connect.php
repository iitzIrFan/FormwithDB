<?php
// Validate and sanitize user input
$firstName = filter_var($_POST['firstName'], FILTER_SANITIZE_STRING);
$lastName = filter_var($_POST['lastName'], FILTER_SANITIZE_STRING);
$gender = filter_var($_POST['gender'], FILTER_SANITIZE_STRING);
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
$password = $_POST['password']; // Note: Password should be hashed (see next point)
$number = filter_var($_POST['number'], FILTER_SANITIZE_NUMBER_INT);

// Password hashing for security
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// Database connection
$conn = new mysqli('localhost', 'root', '', 'test');
if ($conn->connect_error) {
    echo "$conn->connect_error";
    die("Connection Failed: " . $conn->connect_error);
} else {
    $stmt = $conn->prepare("INSERT INTO registration (firstName, lastName, gender, email, password, number) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssi", $firstName, $lastName, $gender, $email, $hashedPassword, $number);
    
    // Execute the statement
    $execVal = $stmt->execute();

    if ($execVal) {
        echo "Registration successful...";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>
