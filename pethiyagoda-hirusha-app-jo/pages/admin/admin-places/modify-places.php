<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Inclure le fichier de connexion à la base de données
require_once("../../../database/database.php");

// Fonction pour vérifier le token CSRF
function checkCSRFToken() {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Token CSRF invalide.');
    }
}

// Vérifier si l'ID du lieu est fourni
if (!isset($_GET['id_lieu'])) {
    die('ID du lieu non spécifié.');
}

$id_lieu = $_GET['id_lieu'];

// Récupérer les informations actuelles du lieu
try {
    $query = "SELECT nom_lieu, adresse_lieu, cp_lieu, ville_lieu FROM LIEU WHERE id_lieu = :id_lieu";
    $statement = $connexion->prepare($query);
    $statement->bindParam(':id_lieu', $id_lieu, PDO::PARAM_INT);
    $statement->execute();
    $lieu = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$lieu) {
        die('Lieu non trouvé.');
    }
} catch (PDOException $e) {
    die("Erreur lors de la récupération des données : " . $e->getMessage());
}

// Traitement du formulaire de modification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCSRFToken();

    $nom_lieu = $_POST['nom_lieu'];
    $adresse_lieu = $_POST['adresse_lieu'];
    $cp_lieu = $_POST['cp_lieu'];
    $ville_lieu = $_POST['ville_lieu'];

    try {
        $query = "UPDATE LIEU SET nom_lieu = :nom_lieu, adresse_lieu = :adresse_lieu, cp_lieu = :cp_lieu, ville_lieu = :ville_lieu WHERE id_lieu = :id_lieu";
        $statement = $connexion->prepare($query);
        $statement->bindParam(':nom_lieu', $nom_lieu, PDO::PARAM_STR);
        $statement->bindParam(':adresse_lieu', $adresse_lieu, PDO::PARAM_STR);
        $statement->bindParam(':cp_lieu', $cp_lieu, PDO::PARAM_STR);
        $statement->bindParam(':ville_lieu', $ville_lieu, PDO::PARAM_STR);
        $statement->bindParam(':id_lieu', $id_lieu, PDO::PARAM_INT);
        $statement->execute();

        // Redirection vers la page de gestion des lieux après modification
        header('Location: manage-places.php');
        exit();
    } catch (PDOException $e) {
        $error_message = "Erreur lors de la modification du lieu : " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Modifier un Lieu - Jeux Olympiques 2024</title>
    <link rel="stylesheet" href="../../../css/styles-computer.css">
    <link rel="stylesheet" href="../../../css/styles-responsive.css">
    <link rel="shortcut icon" href="../../../img/favicon.ico" type="image/x-icon">
</head>
<body>
    <header>
        <nav>
            <ul class="menu">
                <li><a href="../admin.php">Accueil Administration</a></li>
                <li><a href="../admin-sports/manage-sports.php">Gestion Sports</a></li>
                <li><a href="manage-places.php">Gestion Lieux</a></li>
                <li><a href="../admin-countries/manage-countries.php">Gestion Pays</a></li>
                <li><a href="../admin-events/manage-events.php">Gestion Epreuves</a></li>
                <li><a href="../admin-athletes/manage-athletes.php">Gestion Athlètes</a></li>
                <li><a href="../admin-results/manage-results.php">Gestion Résultats</a></li>
                <li><a href="../logout.php">Déconnexion</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <h1>Modifier un Lieu</h1>
        <?php
        if (isset($error_message)) {
            echo "<p class='error'>$error_message</p>";
        }
        ?>
        <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            
            <label for="nom_lieu">Nom du lieu :</label>
            <input type="text" id="nom_lieu" name="nom_lieu" value="<?php echo htmlspecialchars($lieu['nom_lieu']); ?>" required>

            <label for="adresse_lieu">Adresse :</label>
            <input type="text" id="adresse_lieu" name="adresse_lieu" value="<?php echo htmlspecialchars($lieu['adresse_lieu']); ?>" required>

            <label for="cp_lieu">Code postal :</label>
            <input type="text" id="cp_lieu" name="cp_lieu" value="<?php echo htmlspecialchars($lieu['cp_lieu']); ?>" required>

            <label for="ville_lieu">Ville :</label>
            <input type="text" id="ville_lieu" name="ville_lieu" value="<?php echo htmlspecialchars($lieu['ville_lieu']); ?>" required>

            <input type="submit" value="Modifier le lieu">
        </form>
        <p class="paragraph-link">
            <a class="link-home" href="manage-places.php">Retour à la gestion des lieux</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>
</html>