<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Résultats des épreuves - Jeux Olympiques - Los Angeles 2028</title>
    <link rel="stylesheet" href="../css/normalize.css">
    <link rel="stylesheet" href="../css/styles-computer.css">
    <link rel="stylesheet" href="../css/styles-responsive.css">
    <link rel="shortcut icon" href="../img/favicon.ico" type="image/x-icon">

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

        /* Filters section */
        .filters {
            margin: 20px 0;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }

        .filters form {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filters select, .filters input[type="submit"] {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .filters input[type="submit"] {
            background-color: #0066cc;
            color: white;
            cursor: pointer;
            border: none;
            padding: 8px 15px;
        }

        .filters input[type="submit"]:hover {
            background-color: #0052a3;
        }

        .medal-gold {
            color: #FFD700;
            font-weight: bold;
        }

        .medal-silver {
            color: #C0C0C0;
            font-weight: bold;
        }

        .medal-bronze {
            color: #CD7F32;
            font-weight: bold;
        }

        /* Responsive styles */
        @media screen and (max-width: 1024px) {
            main {
                padding: 1rem;
            }

            h1 {
                font-size: 1.5rem;
                margin: 1rem 0;
            }

            .filters form {
                flex-direction: column;
                gap: 10px;
            }

            .filters select, .filters input[type="submit"] {
                width: 100%;
            }

            .table {
                width: 100%;
                margin: 0;
                padding: 0;
            }

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

            .table-container {
                overflow-x: hidden;
                margin: 0 -1rem;
                padding: 0 1rem;
            }
        }

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
        <h1>Résultats des épreuves</h1>

        <?php
        require_once("../database/database.php");

        // Get sports for filter
        $sportQuery = "SELECT * FROM SPORT ORDER BY nom_sport";
        $sports = $connexion->query($sportQuery);

        // Get countries for filter
        $paysQuery = "SELECT * FROM PAYS ORDER BY nom_pays";
        $pays = $connexion->query($paysQuery);
        ?>

        <div class="filters">
            <form method="GET" action="">
                <select name="sport">
                    <option value="">Tous les sports</option>
                    <?php while($sport = $sports->fetch(PDO::FETCH_ASSOC)) { ?>
                        <option value="<?php echo $sport['id_sport']; ?>" 
                            <?php echo (isset($_GET['sport']) && $_GET['sport'] == $sport['id_sport']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($sport['nom_sport']); ?>
                        </option>
                    <?php } ?>
                </select>

                <select name="pays">
                    <option value="">Tous les pays</option>
                    <?php while($pay = $pays->fetch(PDO::FETCH_ASSOC)) { ?>
                        <option value="<?php echo $pay['id_pays']; ?>"
                            <?php echo (isset($_GET['pays']) && $_GET['pays'] == $pay['id_pays']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($pay['nom_pays']); ?>
                        </option>
                    <?php } ?>
                </select>

                <input type="submit" value="Filtrer">
            </form>
        </div>

        <?php
        // Base query
        $sql = "SELECT e.date_epreuve, s.nom_sport, e.nom_epreuve, 
                       a.nom_athlete, a.prenom_athlete, p.nom_pays, pa.resultat
                FROM PARTICIPER pa
                INNER JOIN ATHLETE a ON pa.id_athlete = a.id_athlete
                INNER JOIN PAYS p ON a.id_pays = p.id_pays
                INNER JOIN EPREUVE e ON pa.id_epreuve = e.id_epreuve
                INNER JOIN SPORT s ON e.id_sport = s.id_sport
                WHERE pa.resultat IS NOT NULL ";

        // Add filters if selected
        if(isset($_GET['sport']) && !empty($_GET['sport'])) {
            $sql .= " AND s.id_sport = " . intval($_GET['sport']);
        }
        if(isset($_GET['pays']) && !empty($_GET['pays'])) {
            $sql .= " AND p.id_pays = " . intval($_GET['pays']);
        }

        $sql .= " ORDER BY e.date_epreuve, e.heure_epreuve, pa.resultat";

        $result = $connexion->query($sql);
        ?>

        <div class="table-container">
            <table class="table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Sport</th>
                        <th>Épreuve</th>
                        <th>Athlète</th>
                        <th>Pays</th>
                        <th>Résultat</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $result->fetch(PDO::FETCH_ASSOC)) { ?>
                        <tr>
                            <td data-label="Date"><?php echo date('d/m/Y', strtotime($row['date_epreuve'])); ?></td>
                            <td data-label="Sport"><?php echo htmlspecialchars($row['nom_sport']); ?></td>
                            <td data-label="Épreuve"><?php echo htmlspecialchars($row['nom_epreuve']); ?></td>
                            <td data-label="Athlète"><?php echo htmlspecialchars($row['nom_athlete'] . ' ' . $row['prenom_athlete']); ?></td>
                            <td data-label="Pays"><?php echo htmlspecialchars($row['nom_pays']); ?></td>
                            <td data-label="Résultat">
                            <?php 
                            $medal = '';
                            $displayResult = $row['resultat']; // Original time result

                            // Check if this is the fastest time (winner)
                            if(strpos(strtolower($displayResult), 'vainqueur') !== false) {
                                $medal = 'medal-gold';
                            } 

                            // Display the time result with appropriate medal color
                            ?>
                            <span class="<?php echo $medal; ?>"><?php echo htmlspecialchars($displayResult); ?></span>
                            </td>

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