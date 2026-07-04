import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";

const app = express();
const port = 3000;

const filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

const { Pool } = pg;

const db = new Pool({
  user: "clara",
  host: "127.0.0.1",
  database: "clinica_db",
  password: "password",
  port: 8000,
  ssl: {
    rejectUnauthorized: false, //requisição pro tls
  },
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(dirname, "../front_end")));

app.post("/cadastrar", async (req, res) => {
  const { name, cpf, diagnosis } = req.body;

  try {
    await db.query(
      `INSERT INTO patients (name, cpf, diagnosis) VALUES ($1, $2, $3)`,
      [name, cpf, diagnosis],
    );

    console.log("Paciente cadastrado:", name);

    res.send(`
      <h2>Paciente cadastrado!</h2>
      <a href="/">Voltar</a>
    `);
  } catch (error) {
    console.error(error);
    res.status(500).send("Erro ao cadastrar paciente");
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(dirname, "index.html"));
});

app.post("/cadastrar_medico", async (req, res) => {
  const { name, crm, specialty } = req.body;

  try {
    await db.query(
      `
      INSERT INTO doctors (name, crm, specialty)
      VALUES ($1, $2, $3)
      `,
      [name, crm, specialty],
    );

    console.log("Médico cadastrado:", name);

    res.send("Médico cadastrado!");
  } catch (error) {
    console.error(error);
    res.status(500).send("Erro ao cadastrar médico");
  }
});

app.get("/buscar", async (req, res) => {
  const nomeBuscado = req.query.nome || req.query.name || req.query.cpf; // Pega o nome vindo do frontend

  try {
    const query = "SELECT * FROM patients WHERE name ILIKE $1";
    const values = [`%${nomeBuscado}%`];

    // Aqui fazemos a consulta que vai passar pelo Gateway
    const result = await db.query(query, values);

    if (result.rows.length) {
      let patientsHTML = result.rows.map(row => `<pre>${JSON.stringify(row, null, 2)}</pre>`).join("");
      res.send(`
        <h2>${result.rows.length} Paciente(s) encontrado(s)!</h2>
        ${patientsHTML}
        <a href="/">Voltar</a>
      `);
    } else {
      res.send(`
        <p>Nenhum paciente encontrado com esse nome.</p>
        <a href="/">Voltar</a>
      `);
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Erro na busca");
  }
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
