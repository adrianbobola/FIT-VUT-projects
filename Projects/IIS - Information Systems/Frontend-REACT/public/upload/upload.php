<!--
 * @author Adrian Bobola (xbobol00)
 * @file Backend for upload server
//-->

<html>
<?php
$target_dir = "files/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
$link = "";

// check if filename is different than files on a server.
if (file_exists($target_file)) {
    echo "<html><body><h1>Zmente prosim nazov suboru, dany subor uz existuje!</h1></body></html>";
    $uploadOk = 0;
}

// file size limit
if ($_FILES["fileToUpload"]["size"] > (100 * 1024 * 1024)) { 
    echo "<html><body><h1>Prilis velky subor!</h1></body></html>";
    $uploadOk = 0;
}

if ($uploadOk != 0) {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
	echo "<h1>Subor uspesne nahrany na server.</h1><br>Adresa súboru:<br>http://ituprojekt.fun/upload/files/". basename( $_FILES["fileToUpload"]["name"])."<br>";
    } else {
        echo "<html><body><h1>Nastala chyba pri uploade, skuste to znovu</h1></body></html>";
    }
}
?>

<!-- navigation button with automatic redirect -->
<br>
<button onclick="location.href = 'http://ituprojekt.fun/uzivatel';" class="float-left submit-button" >Napäť</button>
<br>
<meta http-equiv="refresh" content="10; url=http://ituprojekt.fun/uzivatel" />
<p>Budete automaticky presmerovaný o 10 sekúnd</p>
</html>