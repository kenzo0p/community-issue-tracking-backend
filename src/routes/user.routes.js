import { Router } from "express";
import {
  changeUserPassword,
  deleteUserAccount,
  getCurrentUserProfile,
  login,
  registerUser,
  signoutUser,
  updateUserProfile,
} from "../controllers/user.controllers.js";
import { isAuthenticated } from "../middlewares/auth.middleware.js";
import upload from "../util/multer.js";
const userRouter = Router();

//Auth routes
userRouter.route("/signup").post(registerUser);
userRouter.route("/login").post(login);
userRouter.route("/signout").post(signoutUser);

//Profile routes
userRouter.route("/profile").get(isAuthenticated, getCurrentUserProfile);
userRouter
  .route("/profile")
  .patch(isAuthenticated, upload.single("avatar"), updateUserProfile);

//password management
userRouter.route("/change-password").patch(isAuthenticated, changeUserPassword);

//Account management
userRouter.route("/account").delete(isAuthenticated, deleteUserAccount);

//TODO: Forogot password routes when email implementation done

export default userRouter;
