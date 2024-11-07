<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

require_once("../../../database/database.php");

// Récupérer les athlètes avec leur pays
$query_athletes = "SELECT a.id_athlete, a.nom_athlete, a.prenom_athlete, p.nom_pays 
                  FROM ATHLETE a 
                  JOIN PAYS p ON a.id_pays = p.id_pays";
$statement_athletes = $connexion->prepare($query_athletes);
$statement_athletes->execute();
$athletes = $statement_athletes->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les épreuves avec leur sport
$query_events = "SELECT e.id_epreuve, e.nom_epreuve, e.date_epreuve, e.heure_epreuve, s.nom_sport 
                FROM EPREUVE e 
                JOIN SPORT s ON e.id_sport = s.id_sport";
$statement_events = $connexion->prepare($query_events);
$statement_events->execute();
$events = $statement_events->fetchAll(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $id_athlete = $_POST['id_athlete'];
    $id_epreuve = $_POST['id_epreuve'];
    $resultat = $_POST['resultat'];

    try {
        $query = "INSERT INTO PARTICIPER (id_athlete, id_epreuve, resultat) VALUES (:id_athlete, :id_epreuve, :resultat)";
        $statement = $connexion->prepare($query);
        $statement->bindParam(':id_athlete', $id_athlete);
        $statement->bindParam(':id_epreuve', $id_epreuve);
        $statement->bindParam(':resultat', $resultat);
        $statement->execute();

        header('Location: manage-results.php');
        exit();
    } catch (PDOException $e) {
        echo "Erreur : " . htmlspecialchars($e->getMessage());
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
        <title>Ajouter une Résultat - Jeux Olympiques 2024</title>
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
        <h1>Ajouter un Résultat</h1>
        <form action="" method="POST">
            <div class="form-group">
                <label for="id_athlete">Athlète :</label>
                <select id="id_athlete" name="id_athlete" required>
                    <option value="">Sélectionnez un athlète</option>
                    <?php foreach ($athletes as $athlete): ?>
                        <option value="<?php echo $athlete['id_athlete']; ?>">
                            <?php echo htmlspecialchars($athlete['prenom_athlete'] . ' ' . $athlete['nom_athlete'] . 
                                  ' (' . $athlete['nom_pays'] . ')'); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="id_epreuve">Épreuve :</label>
                <select id="id_epreuve" name="id_epreuve" required>
                    <option value="">Sélectionnez une épreuve</option>
                    <?php foreach ($events as $event): ?>
                        <option value="<?php echo $event['id_epreuve']; ?>">
                            <?php echo htmlspecialchars($event['nom_epreuve'] . ' - ' . 
                                  $event['nom_sport'] . ' - ' . 
                                  date('d/m/Y', strtotime($event['date_epreuve'])) . ' ' . 
                                  $event['heure_epreuve']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="resultat">Résultat :</label>
                <input type="text" id="resultat" name="resultat" required>
            </div>

            <input type="submit" class="submit-button" value="Ajouter le résultat">
        </form>
        <p class="paragraph-link">
            <a class="link-home" href="manage-results.php">Retour à la gestion des Résultats</a>
        </p>
    </main>
</body>
</html>