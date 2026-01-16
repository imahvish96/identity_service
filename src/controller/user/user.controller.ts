import {Request, Response} from "express";
import {getUserByName} from "../../repositories/user.repo";

export const getUserDetails = async (req: Request, res: Response) => {
    const {username} = req.body;
    const result = await getUserByName(username);
    if (!result) {
        return res.status(404).json({
            code: "USER_NOT_FOUND",
            message: "User not found",
        })
    }
    
    return res.status(200).json({
        code: "USER_RETRIEVED_SUCCESSFULLY",
        message: "Successfully retrieved user",
        users: result,
    });
}
