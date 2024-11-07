<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

$login = $_SESSION['login'];
$nom_utilisateur = $_SESSION['prenom_utilisateur'];
$prenom_utilisateur = $_SESSION['nom_utilisateur'];

// Vérification du jeton CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Erreur de validation CSRF.');
    }
}

// Génération d'un nouveau jeton CSRF
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

require_once("../../../database/database.php");

// Récupération de l'ID de l'épreuve à modifier
$id_epreuve = isset($_GET['id_epreuve']) ? $_GET['id_epreuve'] : null;

if (!$id_epreuve) {
    die("ID de l'épreuve non spécifié.");
}

// Récupération des informations de l'épreuve
try {
    $query = "SELECT * FROM EPREUVE WHERE id_epreuve = :id_epreuve";
    $statement = $connexion->prepare($query);
    $statement->bindParam(':id_epreuve', $id_epreuve, PDO::PARAM_INT);
    $statement->execute();
    $epreuve = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$epreuve) {
        die("Épreuve non trouvée.");
    }
} catch (PDOException $e) {
    die("Erreur lors de la récupération de l'épreuve : " . $e->getMessage());
}

// Traitement du formulaire de modification
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $nom_epreuve = $_POST['nom_epreuve'];
    $date_epreuve = $_POST['date_epreuve'];
    $heure_epreuve = $_POST['heure_epreuve'];
    $id_sport = $_POST['id_sport'];
    $id_lieu = $_POST['id_lieu'];

    try {
        $query = "UPDATE EPREUVE SET nom_epreuve = :nom_epreuve, date_epreuve = :date_epreuve, heure_epreuve = :heure_epreuve, id_sport = :id_sport, id_lieu = :id_lieu WHERE id_epreuve = :id_epreuve";
        $statement = $connexion->prepare($query);
        $statement->execute([
            ':nom_epreuve' => $nom_epreuve,
            ':date_epreuve' => $date_epreuve,
            ':heure_epreuve' => $heure_epreuve,
            ':id_sport' => $id_sport,
            ':id_lieu' => $id_lieu,
            ':id_epreuve' => $id_epreuve
        ]);

        // Redirection vers la page de gestion des épreuves avec un message de succès
        header("Location: manage-events.php?success=2");
        exit();
    } catch (PDOException $e) {
        $error_message = "Erreur lors de la modification de l'épreuve : " . $e->getMessage();
    }
}

// Récupération de la liste des sports
$query_sports = "SELECT id_sport, nom_sport FROM SPORT";
$statement_sports = $connexion->prepare($query_sports);
$statement_sports->execute();
$sports = $statement_sports->fetchAll(PDO::FETCH_ASSOC);

// Récupération de la liste des lieux
$query_lieux = "SELECT id_lieu, nom_lieu FROM LIEU";
$statement_lieux = $connexion->prepare($query_lieux);
$statement_lieux->execute();
$lieux = $statement_lieux->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../../../css/normalize.css">
    <link rel="stylesheet" href="../../../css/styles-computer.css">
    <link rel="stylesheet" href="../../../css/styles-responsive.css">
    <link rel="shortcut icon" href="../../../img/favicon.ico" type="image/x-icon">
    <title>Modifier une épreuve - Jeux Olympiques 2024</title>
    <style>
        /* Ajoutez ici vos styles CSS personnalisés */
    </style>
</head>

<body>
<header>
        <nav>
            <ul class="menu">
                <li><a href="../admin.php">Accueil Administration</a></li>
                <li><a href="../admin-sports/manage-sports.php">Gestion Sports</a></li>
                <li><a href="../admin-places/manage-places.php">Gestion Lieux</a></li>
                <li><a href="../admin-countries/manage-countries.php">Gestion Pays</a></li>
                <li><a href="../admin-events/manage-events.php">Gestion Epreuves</a></li>
                <li><a href="../admin-athletes/manage-athletes.php">Gestion Athlètes</a></li>
                <li><a href="../admin-results/manage-results.php">Gestion Résultats</a></li>
                <li><a href="../logout.php">Déconnexion</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <h1>Modifier une épreuve</h1>
        <?php
        if (isset($error_message)) {
            echo "<p class='error'>$error_message</p>";
        }
        ?>
        <form action="modify-events.php?id_epreuve=<?= $id_epreuve ?>" method="post">
            <label for="nom_epreuve">Nom de l'épreuve :</label>
            <input type="text" id="nom_epreuve" name="nom_epreuve" value="<?= htmlspecialchars($epreuve['nom_epreuve']) ?>" required>

            <label for="date_epreuve">Date de l'épreuve :</label>
            <input type="date" id="date_epreuve" name="date_epreuve" value="<?= $epreuve['date_epreuve'] ?>" required>

            <label for="heure_epreuve">Heure de l'épreuve :</label>
            <input type="time" id="heure_epreuve" name="heure_epreuve" value="<?= $epreuve['heure_epreuve'] ?>" required>

            <label for="id_sport">Sport :</label>
            <select id="id_sport" name="id_sport" required>
                <?php foreach ($sports as $sport): ?>
                    <option value="<?= $sport['id_sport'] ?>" <?= $sport['id_sport'] == $epreuve['id_sport'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($sport['nom_sport']) ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <label for="id_lieu">Lieu :</label>
            <select id="id_lieu" name="id_lieu" required>
                <?php foreach ($lieux as $lieu): ?>
                    <option value="<?= $lieu['id_lieu'] ?>" <?= $lieu['id_lieu'] == $epreuve['id_lieu'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($lieu['nom_lieu']) ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

            <input type="submit" value="Modifier l'épreuve">
        </form>
        <p class="paragraph-link">
            <a class="link-home" href="manage-events.php">Retour à la gestion des épreuves</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt ="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>

</html>