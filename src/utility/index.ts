import crypto from "crypto";
import jwt from "jsonwebtoken";

export function isValidEmail(email: string) {
    // A common regex pattern for email validation (RFC 5322 standard is complex, this is a practical balance)
    const emailRegex = new RegExp(
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    );

    return emailRegex.test(email);
}


export function generateOTP(): string {
    const otp = crypto.randomInt(100000, 999999);
    return otp.toString();
}

export const generateAccessToken = (userId: string) => {
    return jwt.sign(
        {userId},
        process.env.ACCESS_TOKEN_SECRET!,
        {expiresIn: "15m"}
    );
};

export const generateRefreshToken = (userId: string) => {
    return jwt.sign(
        {userId},
        process.env.REFRESH_TOKEN_SECRET!,
        {expiresIn: "7d"}
    );
};

export const generateVerifyToken = (userId: string) => {
    return jwt.sign(
        {userId},
        process.env.VERIFY_TOKEN_SECRET!,
        {expiresIn: "10m"}
    );
};

export const encrypt = (otp: string): string => {
    return crypto.createHash('sha256').update(otp).digest('hex');
};