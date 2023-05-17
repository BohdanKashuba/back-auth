import { mongoose } from "mongoose";
import bcrypt from "bcrypt";
const Schema = mongoose.Schema;
const SALT_WORK_FACTOR = 10;

const UserSchema = new Schema({
  firstName: {
    type: String,
    set: (v) => v.trim()[0].toUpperCase() + v.slice(1).toLowerCase(),
  },
  lastName: {
    type: String,
    set: (v) => v.trim()[0].toUpperCase() + v.slice(1).toLowerCase(),
  },
  email: { type: String, unique: true },
  phoneNumber: { type: String },
  password: {
    type: String,
  },
  deprecated: { type: Boolean, required: true, default: false },
  deprecatedDate: { type: Date },
  type: [
    {
      type: String,
      enum: ["host", "guest", "admin"],
      default: "user",
    },
  ],
  profilePicture: {
    key: { type: String },
    url: { type: String },
  },
  auth0: { type: String, required: false },
  googleOauth2: { type: String, required: false },
  authToken: { type: String },
  verificationToken: { type: String },
  twoFactorCode: { type: String },
  notifyTokens: [
    {
      deviceType: { type: String },
      value: { type: String },
    },
  ],
});

UserSchema.pre("save", async function (next) {
  try {
    const user = this;
    if (null == user.property) {
      user.property = undefined; // will cause an $unset
    }
    if (!user.isModified("password")) return next();
    const salt = await bcrypt.genSalt(SALT_WORK_FACTOR);
    user.password = await bcrypt.hash(user.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});
// make timestamps true by default
UserSchema.set("timestamps", true);

UserSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const UserModel = mongoose.model("users", UserSchema);

export default UserModel;
