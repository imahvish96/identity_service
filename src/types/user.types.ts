export interface User {
    id: string;
    username: string;
    email: string;
    password_hash: string;
    is_verified: boolean;
    is_active: boolean;
    created_at: Date;
}

export interface VerifyPayload {
    userId: string;
    iat: number;
    exp: number;
}