import {NextFunction, Request, Response} from "express";
import jwt from "jsonwebtoken";

export async function authenticate(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({
            code: "TOKEN_EXPIRE",
            message: 'Authentication required',
        })
    }

    const token = authHeader.split(' ')[1];
    try {
        // @ts-ignore
        req.user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!);
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).send({
            code: "TOKEN_INVALID",
            message: 'Invalid token',
        })
    }
}

export async function verifyOTPToken(req: Request, res: Response, next: NextFunction) {
    const verifyHeader = req.headers['x-verify-token'];
    if (!verifyHeader) {
        return res.status(401).send({
            code: "VERIFY_TOKEN_MISSING",
            message: 'Verification token required',
        })
    }

    try {
        // @ts-ignore
        req.user = jwt.verify(verifyHeader as string, process.env.REFRESH_TOKEN_SECRET!);
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).send({
            code: "VERIFY_TOKEN_INVALID",
            message: 'Invalid verification token',
        })
    }
}