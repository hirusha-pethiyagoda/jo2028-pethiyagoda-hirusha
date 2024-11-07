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

// Fonction pour vérifier le token CSRF
function checkCSRFToken() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            die('Token CSRF invalide.');
        }
    }
}

// Générer un token CSRF si ce n'est pas déjà fait
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once("../../../database/database.php");
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
    <title>Gestion des Athlètes - Jeux Olympiques 2024</title>
    <style>
        .success-message {
            color: green;
            font-weight: bold;
            margin: 10px 0;
        }
        .error-message {
            color: red;
            font-weight: bold;
            margin: 10px 0;
        }
        .search-form {
            margin-bottom: 20px;
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
        <h1>Gestion des Athlètes</h1>
        
        <?php
        // Affichage des messages de succès ou d'erreur
        if (isset($_SESSION['success'])) {
            echo '<p class="success-message">' . $_SESSION['success'] . '</p>';
            unset($_SESSION['success']);
        }
        if (isset($_SESSION['error'])) {
            echo '<p class="error-message">' . $_SESSION['error'] . '</p>';
            unset($_SESSION['error']);
        }
        ?>

        <div class="action-buttons">
            <button onclick="openAddAthleteForm()">Ajouter un Athlète</button>
        </div>

        <!-- Formulaire de recherche -->
        <form class="search-form" method="GET" action="">
            <input type="text" name="search" placeholder="Rechercher un athlète..." 
                   value="<?= isset($_GET['search']) ? htmlspecialchars($_GET['search']) : '' ?>">
            
            <input type="submit" value="Rechercher">
        </form>

        <!-- Tableau des athlètes -->
        <?php
        try {
            // Construction de la requête avec les filtres
            $query = "SELECT a.*, p.nom_pays 
                     FROM ATHLETE a 
                     JOIN PAYS p ON a.id_pays = p.id_pays 
                     WHERE 1=1";
            $params = array();

            if (isset($_GET['search']) && !empty($_GET['search'])) {
                $search = '%' . $_GET['search'] . '%';
                $query .= " AND (a.nom_athlete LIKE :search OR a.prenom_athlete LIKE :search)";
                $params[':search'] = $search;
            }

            if (isset($_GET['country']) && !empty($_GET['country'])) {
                $query .= " AND a.id_pays = :country";
                $params[':country'] = $_GET['country'];
            }

            $query .= " ORDER BY a.nom_athlete, a.prenom_athlete";
            
            $statement = $connexion->prepare($query);
            $statement->execute($params);

            if ($statement->rowCount() > 0) {
                echo "<table>
                        <tr>
                            <th>Nom</th>
                            <th>Prénom</th>
                            <th>Pays</th>
                            <th>Modifier</th>
                            <th>Supprimer</th>
                        </tr>";

                while ($athlete = $statement->fetch(PDO::FETCH_ASSOC)) {
                    echo "<tr>";
                    echo "<td>" . htmlspecialchars($athlete['nom_athlete']) . "</td>";
                    echo "<td>" . htmlspecialchars($athlete['prenom_athlete']) . "</td>";
                    echo "<td>" . htmlspecialchars($athlete['nom_pays']) . "</td>";
                    echo "<td><button onclick='openModifyAthleteForm(" . $athlete['id_athlete'] . ")'>Modifier</button></td>";
                    echo "<td><button onclick='deleteAthleteConfirmation(" . $athlete['id_athlete'] . ")'>Supprimer</button></td>";
                    echo "</tr>";
                }

                echo "</table>";
            } else {
                echo "<p>Aucun athlète trouvé.</p>";
            }
        } catch (PDOException $e) {
            echo "Erreur : " . htmlspecialchars($e->getMessage());
        }
        ?>

        <p class="paragraph-link">
            <a class="link-home" href="../admin.php">Retour à l'accueil de l'administration</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>

    <script>
        function openAddAthleteForm() {
            window.location.href = 'add-athlete.php';
        }

        function openModifyAthleteForm(id_athlete) {
            window.location.href = 'modify-athlete.php?id_athlete=' + id_athlete;
        }

        function deleteAthleteConfirmation(id_athlete) {
            if (confirm("Ê tes-vous sûr de vouloir supprimer cet athlète ?")) {
                window.location.href = 'delete-athlete.php?id_athlete=' + id_athlete;
            }
        }
    </script>
</body>

</html>