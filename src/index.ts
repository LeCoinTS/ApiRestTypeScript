import express, { Request, Response, NextFunction, Express } from "express"
import argon2 from "argon2"
import SQLiteDatabase from "better-sqlite3"

// Initialisation
const app: Express = express()
const bdd: SQLiteDatabase.Database = new SQLiteDatabase("utilisateurs.db")
const PORT: number = 3000

app.use(express.json())

// Interface utilisateur
interface Utilisateur {
  id: number
  nomutilisateur: string
  motdepasse: string
  email: string
}

// Création de la table utilisateur
bdd.exec(`
  CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nomutilisateur TEXT UNIQUE NOT NULL,
    motdepasse TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL
  )
`)

// Middleware de validation basique
const validateUserInput = (req: Request, res: Response, next: NextFunction): void => {
  const { nomutilisateur, motdepasse, email } = req.body as Partial<Utilisateur>
  if (!nomutilisateur || !motdepasse || !email) {
    res.status(400).json({ erreur: "Tous les champs sont requis" })
    return
  }
  next()
}

// CREATE - Créer un nouvel utilisateur
app.post("/utilisateurs", validateUserInput, async (req: Request, res: Response): Promise<void> => {
  try {
    const { nomutilisateur, motdepasse, email } = req.body as Omit<Utilisateur, "id">
    const motdepasse_hashed: string = await argon2.hash(motdepasse)

    const requete_preparee: SQLiteDatabase.Statement<string[], unknown> = bdd.prepare(
      "INSERT INTO utilisateurs (nomutilisateur, motdepasse, email) VALUES (?, ?, ?)"
    )
    const result: SQLiteDatabase.RunResult = requete_preparee.run(nomutilisateur, motdepasse_hashed, email)

    const nouvelUtilisateur: Omit<Utilisateur, "motdepasse"> = {
      id: Number(result.lastInsertRowid),
      nomutilisateur,
      email,
    }

    res.status(201).json(nouvelUtilisateur)
  } catch {
    res.status(400).json({ erreur: "Erreur lors de la création de l'utilisateur" })
  }
})

// READ - Récupérer tous les utilisateurs
app.get("/utilisateurs", (req: Request, res: Response): void => {
  try {
    const requete_preparee: SQLiteDatabase.Statement<string[], unknown> = bdd.prepare("SELECT id, nomutilisateur, email FROM utilisateurs")
    const utilisateurs: Omit<Utilisateur, "motdepasse">[] = requete_preparee.all() as Omit<Utilisateur, "motdepasse">[]
    res.status(200).json(utilisateurs)
  } catch {
    res.status(500).json({ erreur: "Erreur lors de la récupération des utilisateurs" })
  }
})

// READ - Récupérer un utilisateur spécifique
app.get("/utilisateurs/:id", (req: Request, res: Response): void => {
  try {
    const requete_preparee: SQLiteDatabase.Statement<string[], unknown> = bdd.prepare(
      "SELECT id, nomutilisateur, email FROM utilisateurs WHERE id = ?"
    )
    const user: Omit<Utilisateur, "motdepasse"> | undefined = requete_preparee.get(req.params.id) as Omit<Utilisateur, "motdepasse"> | undefined

    if (!user) {
      res.status(404).json({ erreur: "Utilisateur non trouvé" })
      return
    }
    res.status(200).json(user)
  } catch {
    res.status(500).json({ erreur: "Erreur lors de la récupération de l'utilisateur" })
  }
})

// UPDATE - Mettre à jour un utilisateur
app.put("/utilisateurs/:id", async (req: Request, res: Response): Promise<void> => {
  try {
    const { nomutilisateur, motdepasse, email } = req.body as Partial<Omit<Utilisateur, "id">>

    if (!nomutilisateur && !motdepasse && !email) {
      res.status(400).json({ erreur: "Au moins un champ doit être fourni (nomutilisateur, motdepasse, ou email)" })
      return
    }

    const updates: Partial<Omit<Utilisateur, "id">> = {
      ...(nomutilisateur && { nomutilisateur: nomutilisateur }),
      ...(motdepasse && { motdepasse: await argon2.hash(motdepasse) }),
      ...(email && { email: email }),
    }

    const requete_preparee: SQLiteDatabase.Statement<string[], unknown> = bdd.prepare(`
      UPDATE utilisateurs 
      SET ${Object.keys(updates)
        .map((key) => `${key} = ?`)
        .join(", ")}
      WHERE id = ?
    `)

    const result: SQLiteDatabase.RunResult = requete_preparee.run(...Object.values(updates), req.params.id)

    if (result.changes === 0) {
      res.status(404).json({ erreur: "Utilisateur non trouvé" })
      return
    }

    res.status(200).json({ message: "Utilisateur mis à jour avec succès" })
  } catch {
    res.status(400).json({ erreur: "Erreur lors de la mise à jour de l'utilisateur" })
  }
})

// DELETE - Supprimer un utilisateur
app.delete("/utilisateurs/:id", (req: Request, res: Response): void => {
  try {
    const requete_preparee: SQLiteDatabase.Statement<string[], unknown> = bdd.prepare("DELETE FROM utilisateurs WHERE id = ?")
    const result: SQLiteDatabase.RunResult = requete_preparee.run(req.params.id)

    if (result.changes === 0) {
      res.status(404).json({ erreur: "Utilisateur non trouvé" })
      return
    }
    res.status(200).json({ message: "Utilisateur supprimé avec succès" })
  } catch {
    res.status(500).json({ erreur: "Erreur lors de la suppression de l'utilisateur" })
  }
})

// BONUS - Vérifier le mot de passe
app.post("/verifier-motdepasse", async (req: Request, res: Response): Promise<void> => {
  try {
    const { nomutilisateur, motdepasse } = req.body

    // Vérification des champs requis
    if (!nomutilisateur || !motdepasse) {
      res.status(400).json({ erreur: "Nom d'utilisateur et mot de passe requis" })
      return
    }

    // Récupérer l'utilisateur depuis la base de données
    const requete_preparee: SQLiteDatabase.Statement<string[], unknown> = bdd.prepare("SELECT motdepasse FROM utilisateurs WHERE nomutilisateur = ?")
    const utilisateur: { motdepasse: string } | undefined = requete_preparee.get(nomutilisateur) as { motdepasse: string } | undefined

    if (!utilisateur) {
      res.status(404).json({ erreur: "Utilisateur non trouvé" })
      return
    }

    // Vérifier si le mot de passe correspond
    const motdepasseValide: boolean = await argon2.verify(utilisateur.motdepasse, motdepasse)

    if (motdepasseValide) {
      res.status(200).json({ message: "Mot de passe correct !" })
    } else {
      res.status(401).json({ erreur: "Mot de passe incorrect, désolé" })
    }
  } catch {
    res.status(500).json({ erreur: "Erreur lors de la vérification du mot de passe" })
  }
})

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
