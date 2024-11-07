<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../css/normalize.css">
    <link rel="stylesheet" href="../css/styles-computer.css">
    <link rel="stylesheet" href="../css/styles-responsive.css">
    <link rel="shortcut icon" href="../img/favicon.ico" type="image/x-icon">
    <title>Calendrier des épreuves - Jeux Olympiques - Los Angeles 2028</title>

    <style>
        /* Desktop styles */
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .table th {
            background-color: #000000;
            font-weight: bold;
        }

        .table tr:hover {
            background-color: #f5f5f5;
        }

        /* Responsive styles */
        @media screen and (max-width: 1024px) {
            /* General page responsiveness */
            main {
                padding: 1rem;
            }

            h1 {
                font-size: 1.5rem;
                margin: 1rem 0;
            }

            /* Table styles for mobile/tablet */
            .table {
                width: 100%;
                margin: 0;
                padding: 0;
            }

            /* Hide table headers */
            .table thead {
                position: absolute;
                overflow: hidden;
                clip: rect(0 0 0 0);
                height: 1px;
                width: 1px;
                margin: -1px;
                padding: 0;
                border: 0;
            }

            .table tr {
                display: block;
                margin-bottom: 1rem;
                border: 1px solid #ddd;
                background-color: #fff;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                transition: transform 0.2s ease;
            }

            .table tr:hover {
                transform: translateX(5px);
                border-left: 3px solid #0066cc;
            }

            .table td {
                display: block;
                text-align: right;
                padding: 0.5rem;
                border-bottom: 1px solid #eee;
            }

            .table td::before {
                content: attr(data-label);
                float: left;
                font-weight: bold;
                text-transform: uppercase;
                color: #666;
            }

            .table tr td:last-child {
                border-bottom: none;
            }

            /* Container for better margins on mobile */
            .table-container {
                overflow-x: hidden;
                margin: 0 -1rem;
                padding: 0 1rem;
            }
        }

        /* Additional styles for very small screens */
        @media screen and (max-width: 480px) {
            .table {
                font-size: 14px;
            }

            .table td {
                padding: 0.4rem;
            }
        }
    </style>
</head>

<body>
    <header>
        <nav>
            <ul class="menu">
                <li><a href="../index.php">Accueil</a></li>
                <li><a href="sports.php">Sports</a></li>
                <li><a href="events.php">Calendrier des épreuves</a></li>
                <li><a href="results.php">Résultats</a></li>
                <li><a href="login.php">Accès administrateur</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <h1>Calendrier des épreuves</h1>

        <?php
        require_once("../database/database.php");

        // SQL Query to get events with their sports
        $sql = "SELECT e.date_epreuve, e.heure_epreuve, s.nom_sport, e.nom_epreuve, l.nom_lieu 
                FROM EPREUVE e
                INNER JOIN SPORT s ON e.id_sport = s.id_sport
                INNER JOIN LIEU l ON e.id_lieu = l.id_lieu
                ORDER BY e.date_epreuve, e.heure_epreuve";

        $result = $connexion->query($sql);
        ?>

        <div class="table-container">
            <table class="table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Heure</th>
                        <th>Sport</th>
                        <th>Épreuve</th>
                        <th>Lieu</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $result->fetch(PDO::FETCH_ASSOC)) { ?>
                        <tr>
                            <td data-label="Date"><?php echo date('d/m/Y', strtotime($row['date_epreuve'])); ?></td>
                            <td data-label="Heure"><?php echo date('H:i', strtotime($row['heure_epreuve'])); ?></td>
                            <td data-label="Sport"><?php echo htmlspecialchars($row['nom_sport']); ?></td>
                            <td data-label="Épreuve"><?php echo htmlspecialchars($row['nom_epreuve']); ?></td>
                            <td data-label="Lieu"><?php echo htmlspecialchars($row['nom_lieu']); ?></td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>

        <p class="paragraph-link">
            <a class="link-home" href="../index.php">Retour Accueil</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../img/logo-jo.png" alt="logo Jeux Olympiques - Los Angeles 2028">
        </figure>
    </footer>
</body>

</html>