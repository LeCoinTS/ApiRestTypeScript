import express, { Request, Response, NextFunction, Express } from "express"
import argon2 from "argon2"
import Database from "better-sqlite3"

// Initialisation
const app: Express = express()
const bdd = new Database("utilisateurs.db")
const PORT = 3000

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
    res.status(400).json({ error: "Tous les champs sont requis" })
    return
  }
  next()
}

// CREATE - Créer un nouvel utilisateur
app.post("/utilisateurs", validateUserInput, async (req: Request, res: Response): Promise<void> => {
  try {
    const { nomutilisateur, motdepasse, email } = req.body as Omit<Utilisateur, "id">
    const motdepasse_hashed = await argon2.hash(motdepasse)

    const stmt = bdd.prepare("INSERT INTO utilisateurs (nomutilisateur, motdepasse, email) VALUES (?, ?, ?)")
    const result = stmt.run(nomutilisateur, motdepasse_hashed, email)

    const nouvelUtilisateur: Omit<Utilisateur, "motdepasse"> = {
      id: Number(result.lastInsertRowid),
      nomutilisateur,
      email,
    }

    res.status(201).json(nouvelUtilisateur)
  } catch (error) {
    res.status(400).json({ error: "Erreur lors de la création de l'utilisateur" })
  }
})

// READ - Récupérer tous les utilisateurs
app.get("/utilisateurs", (req: Request, res: Response): void => {
  try {
    const stmt = bdd.prepare("SELECT id, nomutilisateur, email FROM utilisateurs")
    const utilisateurs = stmt.all() as Omit<Utilisateur, "motdepasse">[]
    res.json(utilisateurs)
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de la récupération des utilisateurs" })
  }
})

// READ - Récupérer un utilisateur spécifique
app.get("/utilisateurs/:id", (req: Request, res: Response): void => {
  try {
    const stmt = bdd.prepare("SELECT id, nomutilisateur, email FROM utilisateurs WHERE id = ?")
    const user = stmt.get(req.params.id) as Omit<Utilisateur, "motdepasse"> | undefined

    if (!user) {
      res.status(404).json({ error: "Utilisateur non trouvé" })
      return
    }
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de la récupération de l'utilisateur" })
  }
})

// UPDATE - Mettre à jour un utilisateur
app.put("/utilisateurs/:id", validateUserInput, async (req: Request, res: Response): Promise<void> => {
  try {
    const { nomutilisateur, motdepasse, email } = req.body as Omit<Utilisateur, "id">
    const motdepasse_hashed = await argon2.hash(motdepasse)

    const stmt = bdd.prepare(`
      UPDATE utilisateurs 
      SET nomutilisateur = ?, motdepasse = ?, email = ?
      WHERE id = ?
    `)
    const result = stmt.run(nomutilisateur, motdepasse_hashed, email, req.params.id)

    if (result.changes === 0) {
      res.status(404).json({ error: "Utilisateur non trouvé" })
      return
    }
    res.json({ message: "Utilisateur mis à jour avec succès" })
  } catch (error) {
    res.status(400).json({ error: "Erreur lors de la mise à jour de l'utilisateur" })
  }
})

// DELETE - Supprimer un utilisateur
app.delete("/utilisateurs/:id", (req: Request, res: Response): void => {
  try {
    const stmt = bdd.prepare("DELETE FROM utilisateurs WHERE id = ?")
    const result = stmt.run(req.params.id)

    if (result.changes === 0) {
      res.status(404).json({ error: "Utilisateur non trouvé" })
      return
    }
    res.json({ message: "Utilisateur supprimé avec succès" })
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de la suppression de l'utilisateur" })
  }
})

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
