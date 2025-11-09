import { AppError, catchAsync } from "../middlewares/error.middlware.js";
import { UserModel } from "../models/user.model.js";
import { deleteMediaFromCloudinary, uploadMedia } from "../util/cloudinary.js";
import { generateToken } from "../util/generateToken.js";

/**
 * Create a new user
 * @route POST /api/v1/user/signup
 *
 */
export const registerUser = catchAsync(async (req, res) => {
  const { firstname, lastname, password, email, role } = req.body;
  const user = await UserModel.findOne({ email });
  if (user) {
    throw new AppError(
      "User exist with the email!, Please enter the correct email",
      400
    );
  }
  const newUser = await UserModel.create({
    firstname: firstname,
    lastname: lastname,
    password: password,
    role: role,
    email: email,
  });

  if (!newUser) {
    throw new AppError("Something went wrong! please try again", 500);
  }

  return res
    .status(201)
    .json({ newUser, message: "User registered successfully! please log in" });
});

/**
 * Authenticate and get token
 * @route POST /api/v1/user/login
 *
 */
export const login = catchAsync(async (req, res) => {
  const { password, email } = req.body;
  const user = await UserModel.findOne({ email }).select("+password");
  if (!user || !(await user.comparePassword(password))) {
    throw new AppError(
      "User does not exist with the email!, Please register the correct user",
      400
    );
  }

  generateToken(res, user._id, `Welcome back ${user.firstname}`);
});

/**
 * Get current user profile
 * @route GET /api/v1/user/signout
 */
export const signoutUser = catchAsync(async (_, res) => {
  res.cookie("token", "", { maxAge: 0 });
  res.status(200).json({
    success: true,
    message: "Signed out successfully",
  });
});

/**
 * Get current user profile
 * @route GET /api/v1/user/profile
 */

export const getCurrentUserProfile = catchAsync(async (req, res) => {
  const user = await UserModel.findById(req.id).populate({
    path: "createdIssues",
    select: "title description imageUrl",
  });
  if (!user) {
    throw new AppError("User not found", 404);
  }
  res.status(200).json({
    success: true,
    data: {
      ...user.toJSON(),
      totalCreatedIssues: user.totalCreatedIssues,
    },
  });
});

export const updateUserProfile = catchAsync(async (req, res) => {
  const { firstname, lastname, email } = req.body;

  const updateData = { firstname, lastname, email: email?.toLowerCase() };

  if (req.file) {
    const avatarResult = await uploadMedia(req.file.path);
    updateData.avatar = avatarResult?.secure_url || req.file.path;

    //Delete old avatar if its not the default
    const user = await UserModel.findById(req.id);
    if (user.avatar && user.avatar !== "default-avatart.png") {
      await deleteMediaFromCloudinary(user.avatar);
    }

    //update the user and get the updated document
    const updatedUser = await UserModel.findByIdAndDelete(req.id, updateData, {
      new: true,
      runValidators: true,
    });

    if (!updatedUser) {
      throw new AppError("User not found", 404);
    }

    res.status(200).json({
      success: true,
      message: "profile updated successfullt",
      data: updatedUser,
    });
  }
});

/**
 * Change user password
 * @route PATCH /api/v1/user/password
 */

export const changeUserPassword = catchAsync(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  //Get user with password;
  const user = await UserModel.findById(req.id).select("+password");

  if (!user) {
    throw new AppError("User  not found", 404);
  }

  //verify the current password
  if (!(await user.comparePassword(currentPassword))) {
    throw new AppError("Current password is incorrect", 404);
  }

  //update the password

  user.password = newPassword;
  await user.save();

  res
    .status(200)
    .json({ success: true, message: "Passoword changes successfully" });
});

/**
 * Request password reset
 * @route POST /api/v1/user/forgot-password
 */

export const forgotPassword = catchAsync(async (req, res) => {
  const { email } = req.body;
  const user = await user.findOne({ email: email.toLowerCase() });

  if (!user) {
    throw new AppError("No User found with this email");
  }

  //Generate reset token
  const resetToken = user.getResetPasswordToken();
  await user.dave({ validateBeforeSave: false });

  //TODO: Send reset token via email

  res.status(200).json({
    success: true,
    message: "Password reset instructions sent to email",
  });
});

/**
 * Reset password
 * @route POST /api/v1/user/reset-password/:token
 */

export const resetPassword = catchAsync(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  //Get user by reset token
  const user = await UserModel.findOne({
    resetPasswordToken: crypto.createHash("sha256").update(token).digest("hex"),
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    throw new AppError("Invalid or expired reset token", 400);
  }

  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  res
    .status(200)
    .json({ success: true, message: "password reset successfully" });
});

/**
 * Delete user account
 * @route DELETE /api/v1/user/account
 */

export const deleteUserAccount = catchAsync(async (req, res) => {
  const user = await UserModel.findById(req.id);

  // Delete avatar if not default
  if (user.avatar && user.avatar !== "default-avatar.png") {
    await deleteMediaFromCloudinary(user.avatar);
  }

  //Delete user

  await UserModel.findByIdAndDelete(req.id);

  res.cookie("token", "", { maxAge: 0 });
  res.status(200).json({
    success: true,
    message: "Account deleted successfully",
  });
});
