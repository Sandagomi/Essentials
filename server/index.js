import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pkg from "@prisma/client";
const { PrismaClient } = pkg;

const app = express();
const prisma = new PrismaClient(); 


const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

async function main() {
    const users = await prisma.user.findMany();
    console.log(users);
}
main()
  .catch(e => console.error(e))
  .finally(async () => await prisma.$disconnect());


app.use(cors({
  origin: CLIENT_URL,
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

function setAuthCookie(res, userId) {
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "1h" });
  res.cookie("auth", token, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 3600000 });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies.auth;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { email, password: hashedPassword },
  });
  setAuthCookie(res, user.id);
  res.json({ success: true });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { email },
  });
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  setAuthCookie(res, user.id);
  res.json({ success: true });
});

app.post("/api/auth/logout", async (req, res) => {
  res.clearCookie("auth");
  res.json({ success: true });
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});