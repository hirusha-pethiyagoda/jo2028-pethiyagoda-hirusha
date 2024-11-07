<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Vérification du jeton CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Erreur de validation CSRF.');
    }
}

// Génération d'un nouveau jeton CSRF
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

require_once("../../../database/database.php");

// Récupération de la liste des pays
try {
    $query_pays = "SELECT * FROM PAYS ORDER BY nom_pays";
    $statement_pays = $connexion->prepare($query_pays);
    $statement_pays->execute();
    $pays = $statement_pays->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur lors de la récupération des pays : " . $e->getMessage();
}

// Récupération de la liste des genres
try {
    $query_genre = "SELECT * FROM GENRE ORDER BY nom_genre";
    $statement_genre = $connexion->prepare($query_genre);
    $statement_genre->execute();
    $genres = $statement_genre->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur lors de la récupération des genres : " . $e->getMessage();
}

// Traitement du formulaire d'ajout
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        // Récupération et validation des données
        $nom_athlete = trim($_POST['nom_athlete']);
        $prenom_athlete = trim($_POST['prenom_athlete']);
        $id_pays = $_POST['id_pays'];
        $id_genre = $_POST['id_genre'];

        // Validation des données
        if (empty($nom_athlete) || empty($prenom_athlete) || empty($id_pays) || empty($id_genre)) {
            throw new Exception("Tous les champs sont obligatoires.");
        }

        // Préparation et exécution de la requête
        $query = "INSERT INTO ATHLETE (nom_athlete, prenom_athlete, id_pays, id_genre) 
                 VALUES (:nom_athlete, :prenom_athlete, :id_pays, :id_genre)";
        
        $statement = $connexion->prepare($query);
        $statement->execute([
            ':nom_athlete' => $nom_athlete,
            ':prenom_athlete' => $prenom_athlete,
            ':id_pays' => $id_pays,
            ':id_genre' => $id_genre
        ]);

        $_SESSION['success'] = "L'athlète a été ajouté avec succès.";
        header("Location: manage-athletes.php");
        exit();

    } catch (Exception $e) {
        $_SESSION['error'] = $e->getMessage();
    }
}
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
        <title>Ajouter un Athlète - Jeux Olympiques 2024</title>
        <style>
        .error-message {
            color: red;
            margin-bottom: 10px;
        }
        form {
            max-width: 600px;
            margin: 0 auto;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"],
        select {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
        }
        .submit-button {
            background-color: #1b1b1b;
            color: white;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
        }
        .submit-button:hover {
            background-color: #333;
        }
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
        <h1>Ajouter un Athlète</h1>

        <?php
        if (isset($_SESSION['error'])) {
            echo '<p class="error-message">' . $_SESSION['error'] . '</p>';
            unset($_SESSION['error']);
        }
        ?>

        <form method="post" action="add-athlete.php">
            <div class="form-group">
                <label for="nom_athlete">Nom :</label>
                <input type="text" id="nom_athlete" name="nom_athlete" required 
                       value="<?= isset($_POST['nom_athlete']) ? htmlspecialchars($_POST['nom_athlete']) : '' ?>">
            </div>

            <div class="form-group">
                <label for="prenom_athlete">Prénom :</label>
                <input type="text" id="prenom_athlete" name="prenom_athlete" required 
                       value="<?= isset($_POST['prenom_athlete']) ? htmlspecialchars($_POST['prenom_athlete']) : '' ?>">
            </div>

            <div class="form-group">
                <label for="id_pays">Pays :</label>
                <select id="id_pays" name="id_pays" required>
                    <option value="">Sélectionnez un pays</option>
                    <?php foreach ($pays as $pays_item): ?>
                        <option value="<?= $pays_item['id_pays'] ?>" 
                            <?= (isset($_POST['id_pays']) && $_POST['id_pays'] == $pays_item['id_pays']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($pays_item['nom_pays']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="id_genre">Genre :</label>
                <select id="id_genre" name="id_genre" required>
                    <option value="">Sélectionnez un genre</option>
                    <?php foreach ($genres as $genre): ?>
                        <option value="<?= $genre['id_genre'] ?>" 
                            <?= (isset($_POST['id_genre']) && $_POST['id_genre'] == $genre['id_genre']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($genre['nom_genre']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="submit" class="submit-button" value="Ajouter l'Athlète">
        </form>

        <p class="paragraph-link">
            <a class="link-home" href="manage-athletes.php">Retour à la gestion des athlètes</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>

</html>