<?php
session_start();
require_once("../../../database/database.php");

// Configuration des erreurs
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Vérification de la connexion
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Génération du token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Récupération de l'ID utilisateur
$userId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT) ?: 0;

if ($userId <= 0) {
    $_SESSION['error'] = "ID utilisateur invalide.";
    header("Location: manage-users.php");
    exit();
}

try {
    // Récupération des informations utilisateur
    $queryUser = "SELECT * FROM UTILISATEUR WHERE id_utilisateur = :userId";
    $statementUser = $connexion->prepare($queryUser);
    $statementUser->bindParam(":userId", $userId, PDO::PARAM_INT);
    $statementUser->execute();
    $user = $statementUser->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $_SESSION['error'] = "Utilisateur non trouvé.";
        header("Location: manage-users.php");
        exit();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur de base de données : " . $e->getMessage();
    header("Location: manage-users.php");
    exit();
}

// Traitement du formulaire
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Vérification du token CSRF
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = "Token CSRF invalide.";
        header("Location: modify-user.php?id=" . $userId);
        exit();
    }

    // Filtrage et validation des données
    $nom = filter_input(INPUT_POST, 'nom', FILTER_SANITIZE_SPECIAL_CHARS);
    $prenom = filter_input(INPUT_POST, 'prenom', FILTER_SANITIZE_SPECIAL_CHARS);
    $login = filter_input(INPUT_POST, 'login', FILTER_SANITIZE_SPECIAL_CHARS);

    // Validation des champs
    if (empty($nom) || empty($prenom) || empty($login)) {
        $_SESSION['error'] = "Tous les champs sont obligatoires.";
        header("Location: modify-user.php?id=" . $userId);
        exit();
    }

    try {
        // Préparation de la requête de mise à jour
        $queryUpdate = "UPDATE UTILISATEUR SET 
                        nom_utilisateur = :nom, 
                        prenom_utilisateur = :prenom, 
                        login = :login";
        $params = [
            ':nom' => $nom,
            ':prenom' => $prenom,
            ':login' => $login,
            ':userId' => $userId
        ];

        // Gestion du changement de mot de passe
        if (!empty($_POST['new_password'])) {
            // Vérification du mot de passe actuel
            $checkPassword = $connexion->prepare("SELECT password FROM UTILISATEUR WHERE id_utilisateur = :userId");
            $checkPassword->bindParam(":userId", $userId, PDO::PARAM_INT);
            $checkPassword->execute();
            $userData = $checkPassword->fetch(PDO::FETCH_ASSOC);

            if (!password_verify($_POST['current_password'], $userData['password'])) {
                $_SESSION['error'] = "Mot de passe actuel incorrect.";
                header("Location: modify-user.php?id=" . $userId);
                exit();
            }

            // Hachage du nouveau mot de passe
            $newPasswordHash = password_hash($_POST['new_password'], PASSWORD_DEFAULT);
            $queryUpdate .= ", password = :password";
            $params[':password'] = $newPasswordHash;
        }

        // Finalisation de la requête
        $queryUpdate .= " WHERE id_utilisateur = :userId";
        $statementUpdate = $connexion->prepare($queryUpdate);
        
        // Exécution de la mise à jour
        if ($statementUpdate->execute($params)) {
            $_SESSION['success'] = "Utilisateur mis à jour avec succès.";
            header("Location: manage-users.php");
            exit();
        } else {
            $_SESSION['error'] = "Erreur lors de la mise à jour de l'utilisateur.";
            header("Location: modify-user.php?id=" . $userId);
            exit();
        }
    } catch (PDOException $e) {
        $_SESSION['error'] = "Erreur de base de données : " . $e->getMessage();
        header("Location: modify-user.php?id=" . $userId);
        exit();
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
    <title>Modifier un Utilisateur - Jeux Olympiques - Los Angeles 2028</title>
</head>
<body>
    <header>
        <nav>
            <ul class="menu">
                <li><a href="../admin.php">Accueil Administration</a></li>
                <li><a href="manage-users.php">Gestion Utilisateurs</a></li>
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
        <h1>Modifier un Utilisateur</h1>
        
        <?php
        // Gestion des messages d'erreur et de succès
        if (isset($_SESSION['error'])) {
            echo '<p class="error">' . htmlspecialchars($_SESSION['error'], ENT_QUOTES, 'UTF-8') . '</p>';
            unset($_SESSION['error']);
        }
        if (isset($_SESSION['success'])) {
            echo '<p class="success">' . htmlspecialchars($_SESSION['success'], ENT_QUOTES, 'UTF-8') . '</p>';
            unset($_SESSION['success']);
        }
        ?>

        <form action="modify-user.php?id=<?= $userId ?>" method="post" 
              onsubmit="return confirm('Êtes-vous sûr de vouloir modifier cet utilisateur ?')">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            
            <label for="nom">Nom :</label>
            <input type="text" name="nom" id="nom" 
                   value="<?= htmlspecialchars($user['nom_utilisateur'], ENT_QUOTES, 'UTF-8') ?>" required>

            <label for="prenom">Prénom :</label>
            <input type="text" name="prenom" id="prenom" 
                   value="<?= htmlspecialchars($user['prenom_utilisateur'], ENT_QUOTES, 'UTF-8') ?>" required>

            <label for="login">Login :</label>
            <input type="text" name="login" id="login" 
                   value="<?= htmlspecialchars($user['login'], ENT_QUOTES, 'UTF-8') ?>" required>

            <label for="current_password">Mot de passe actuel :</label>
            <input type="password" name="current_password" id="current_password" required>

            <label for="new_password">Nouveau mot de passe :</label>
            <input type="password" name="new_password" id="new_password">

            <input type="submit" value="Modifier l'Utilisateur">
        </form>
        <p class="paragraph-link">
            <a class="link-home" href="manage-users.php">Retour à la gestion des utilisateurs</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques - Los Angeles 2028">
        </figure>
    </footer>
</body>
</html>