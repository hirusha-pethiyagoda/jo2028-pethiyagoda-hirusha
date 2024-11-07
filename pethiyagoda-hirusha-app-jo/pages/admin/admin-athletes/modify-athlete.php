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

// Récupération de l'ID de l'athlète depuis l'URL
if (!isset($_GET['id_athlete'])) {
    $_SESSION['error'] = "ID de l'athlète non spécifié.";
    header("Location: manage-athletes.php");
    exit();
}

$id_athlete = intval($_GET['id_athlete']);

// Récupération des informations de l'athlète
try {
    $query = "SELECT * FROM ATHLETE WHERE id_athlete = :id_athlete";
    $statement = $connexion->prepare($query);
    $statement->bindParam(':id_athlete', $id_athlete, PDO::PARAM_INT);
    $statement->execute();
    $athlete = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$athlete) {
        $_SESSION['error'] = "Athlète non trouvé.";
        header("Location: manage-athletes.php");
        exit();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur lors de la récupération de l'athlète : " . $e->getMessage();
    header("Location: manage-athletes.php");
    exit();
}

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

// Traitement du formulaire de modification
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

        // Mise à jour des données
        $query = "UPDATE ATHLETE 
                 SET nom_athlete = :nom_athlete, 
                     prenom_athlete = :prenom_athlete, 
                     id_pays = :id_pays, 
                     id_genre = :id_genre 
                 WHERE id_athlete = :id_athlete";
        
        $statement = $connexion->prepare($query);
        $statement->execute([
            ':nom_athlete' => $nom_athlete,
            ':prenom_athlete' => $prenom_athlete,
            ':id_pays' => $id_pays,
            ':id_genre' => $id_genre,
            ':id_athlete' => $id_athlete
        ]);

        $_SESSION['success'] = "L'athlète a été modifié avec succès.";
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
    <title>Modifier un Athlète - Jeux Olympiques 2024</title>
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
        <h1>Modifier un Athlète</h1>

        <?php
        if (isset($_SESSION['error'])) {
            echo '<p class="error-message">' . $_SESSION['error'] . '</p>';
            unset($_SESSION['error']);
        }
        ?>

        <form method="post" action="modify-athlete.php?id_athlete=<?= $id_athlete ?>">
            <div class="form-group">
                <label for="nom_athlete">Nom :</label>
                <input type="text" id="nom_athlete" name="nom_athlete" required 
                       value="<?= htmlspecialchars($athlete['nom_athlete']) ?>">
            </div>

            <div class="form-group">
                <label for="prenom_athlete">Prénom :</label>
                <input type="text" id="prenom_athlete" name="prenom_athlete" required 
                       value="<?= htmlspecialchars($athlete['prenom_athlete']) ?>">
            </div>

            <div class="form-group">
                <label for="id_pays">Pays :</label>
                <select id="id_pays" name="id_pays" required>
                    <?php foreach ($pays as $pays_item): ?>
                        <option value="<?= $pays_item['id_pays'] ?>" 
                            <?= ($athlete['id_pays'] == $pays_item['id_pays']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($pays_item['nom_pays']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="id_genre">Genre :</label>
                <select id="id_genre" name="id_genre" required>
                    <?php foreach ($genres as $genre): ?>
                        <option value="<?= $genre['id_genre'] ?>" 
                            <?= ($athlete['id_genre'] == $genre['id_genre']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($genre['nom_genre']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="submit" class="submit-button" value="Modifier l'Athlète">
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