import { Request, Response } from "express";
import pool from "../../db";

export const healthCheck = async (req: Request, res: Response) => {
  await pool.query("SELECT 1");
  console.log("DB Connected");
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
  });
};
