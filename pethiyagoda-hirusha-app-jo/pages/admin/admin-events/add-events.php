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

// Traitement du formulaire d'ajout
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Récupération des données du formulaire
    $nom_epreuve = $_POST['nom_epreuve'];
    $date_epreuve = $_POST['date_epreuve'];
    $heure_epreuve = $_POST['heure_epreuve'];
    $id_sport = $_POST['id_sport'];
    $id_lieu = $_POST['id_lieu'];

    try {
        // Préparation de la requête d'insertion
        $query = "INSERT INTO EPREUVE (nom_epreuve, date_epreuve, heure_epreuve, id_sport, id_lieu) VALUES (:nom_epreuve, :date_epreuve, :heure_epreuve, :id_sport, :id_lieu)";
        $statement = $connexion->prepare($query);

        // Exécution de la requête
        $statement->execute([
            ':nom_epreuve' => $nom_epreuve,
            ':date_epreuve' => $date_epreuve,
            ':heure_epreuve' => $heure_epreuve,
            ':id_sport' => $id_sport,
            ':id_lieu' => $id_lieu
        ]);

        // Redirection vers la page de gestion des épreuves avec un message de succès
        header("Location: manage-events.php?success=1");
        exit();
    } catch (PDOException $e) {
        // En cas d'erreur, on affiche un message
        $error_message = "Erreur lors de l'ajout de l'épreuve : " . $e->getMessage();
    }
}

// Récupération de la liste des sports pour le menu déroulant
$query_sports = "SELECT id_sport, nom_sport FROM SPORT";
$statement_sports = $connexion->prepare($query_sports);
$statement_sports->execute();
$sports = $statement_sports->fetchAll(PDO::FETCH_ASSOC);

// Récupération de la liste des lieux pour le menu déroulant
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
    <title>Ajouter une épreuve - Jeux Olympiques 2024</title>
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
        <h1>Ajouter une épreuve</h1>
        <?php
        if (isset($error_message)) {
            echo "<p class='error'>$error_message</p>";
        }
        ?>
        <form action="add-events.php" method="post">
            <label for="nom_epreuve">Nom de l'épreuve :</label>
            <input type="text" id="nom_epreuve" name="nom_epreuve" required>

            <label for="date_epreuve">Date de l'épreuve :</label>
            <input type="date" id="date_epreuve" name="date_epreuve" required>

            <label for="heure_epreuve">Heure de l'épreuve :</label>
            <input type="time" id="heure_epreuve" name="heure_epreuve" required>

            <label for="id_sport">Sport :</label>
            <select id="id_sport" name="id_sport" required>
                <?php foreach ($sports as $sport): ?>
                    <option value="<?= $sport['id_sport'] ?>"><?= htmlspecialchars($sport['nom_sport']) ?></option>
                <?php endforeach; ?>
            </select>

            <label for="id_lieu">Lieu :</label>
            <select id="id_lieu" name="id_lieu" required>
                <?php foreach ($lieux as $lieu): ?>
                    <option value="<?= $lieu['id_lieu'] ?>"><?= htmlspecialchars($lieu['nom_lieu']) ?></option>
                <?php endforeach; ?>
            </select>

            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

            <input type="submit" value="Ajouter l'épreuve">
        </form>
        <p class="paragraph-link">
            <a class="link-home" href="manage-events.php">Retour à la gestion des épreuves</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>

</html>