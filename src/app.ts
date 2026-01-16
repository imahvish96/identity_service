import "dotenv/config"
import express from "express";

var cookieParser = require('cookie-parser')
import routes from "./routes";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use("/api", routes);

export default app;
