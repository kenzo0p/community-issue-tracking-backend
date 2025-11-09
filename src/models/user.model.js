import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import "./issues.model.js"

const userSchema = new mongoose.Schema(
  {
    firstname: {
      type: String,
      required: true,
      trim: true,
      minlength: [2, "firstname should atleast 2 characters"],
    },
    lastname: {
      type: String,
      required: true,
      trim: true,
      minlength: [3, "lastname should atleast 3 characters"],
    },
    avatar :{
      type : String,
      default :"default-avatar.png"
    },
    email: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
      match: [
        /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/,
        "Please provide a valid email",
      ],
    },
    password: {
      type: String,
      required: true,
      minlength: [6, "Password must be at least 6 characters long"],
      select: false, //I dont want to select by default for any api
      maxlength: [128, "Password cannot exceed 128 characters"],
    },
    role: {
      type: String,
      enum: {
        values: ["user", "admin"],
        message: "Please select a valid role",
      },
      default: "user",
    },
    createdIssues: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "Issue",
      },
    ],
    resetPasswordToken: String,
    resetPasswordExpire: Date,
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

//hashing the password hook
userSchema.pre("save", async function (next) {
  // Don't hash again if password is not modified
  if (!this.isModified("password")) {
    return next();
  }
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (err) {
    next(err);
  }
});

userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.getResetPasswordToken = function () {
  /**
   * Generates a secure random token for password reset functionality.
   * @type {string}
   * @description A hexadecimal string token generated using 20 random bytes. //40 chars
   * and reset password expire time 10 min
   */
  const resetToken = crypto.randomBytes(20).toString("hex");
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; //10 min
  return resetToken;
};

userSchema.virtual("totalCreatedIssues").get(function () {
  return this.createdIssues?.length;
});

export const UserModel = mongoose.model("User", userSchema);
