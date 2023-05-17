import { schemaComposer } from "graphql-compose";
import UserModel from "../../database/models/users.model.js";
import { generate2FACode } from "../../helpers/generate2FACode.js";
import { generateJWT } from "../../helpers/index.js";
import { isPhoneNumberValid } from "../../helpers/phoneNumber.js";
import { sendSms } from "../../services/twilio.js";
import UserTC from "../typeDefs/users.js";

const signUp = schemaComposer.createResolver({
  name: "signUp",
  type: UserTC,
  kind: "mutation",
  args: {
    firstName: "String",
    lastName: "String",
    email: "String",
    phoneNumber: "String",
    password: "String",
    confirmPassword: "String",
  },
  resolve: async ({ source, args, context, info }) => {
    try {
      if (args.password !== args.confirmPassword) {
        throw new Error("Password and Confirm Password don't match");
      }
      if (!isPhoneNumberValid(args.phoneNumber)) {
        throw new Error("Phone number doesn't valid");
      }
      const user = await UserModel.findOne({
        $or: [{ email: args.email }, { phoneNumber: args.phoneNumber }],
      });

      if (user) {
        throw new Error(
          `User with email: ${args.email} or phone: ${args.phoneNumber} already exists`
        );
      }
      const newUser = await UserModel.create({
        firstName: args.firstName,
        lastName: args.lastName,
        email: args.email,
        phoneNumber: args.phoneNumber,
        password: args.password,
      });

      return newUser;
    } catch (error) {
      throw new Error(`Unable to create user ${error}`);
    }
  },
});

const signIn = schemaComposer.createResolver({
  name: "signIn",
  type: UserTC,
  kind: "mutation",
  args: {
    email: "String",
    password: "String",
  },
  resolve: async ({ source, args, context, info }) => {
    try {
      const user = await UserModel.findOne({ email: args.email });
      if (!user) {
        throw new Error(`User with email: ${args.email} doesn't exist`);
      }
      const isMatch = await user.comparePassword(args.password);
      if (!isMatch) {
        throw new Error(`Password is wrong`);
      }
      const verificationToken = generateJWT({
        userInfo: { email: args.email },
      });
      const twoFactorCode = generate2FACode();

      user.set({ verificationToken, twoFactorCode });
      await user.save();

      const text = `Hi ${user.firstName}, please confirm your authentication with this code: ${twoFactorCode}.`;
      // await sendSms(user.phoneNumber, text);
      return user;
    } catch (error) {
      throw new Error(`Unable to login user ${error}`);
    }
  },
});

const twoFactorVerification = schemaComposer.createResolver({
  name: "twoFactorVerification",
  type: UserTC,
  kind: "mutation",
  args: {
    verificationToken: "String",
    twoFactorCode: "String",
  },
  resolve: async ({ source, args, context, info }) => {
    try {
      const user = await UserModel.findOne({
        $or: [
          { verificationToken: args.verificationToken },
          { twoFactorCode: args.twoFactorCode },
        ],
      });

      if (!user) {
        throw new Error(`Verification Failed`);
      }

      const authToken = generateJWT({
        userInfo: { email: user.email, id: user._id },
      });
      user.set({ authToken, verificationToken: "" });
      await user.save();

      return user;
    } catch (error) {
      throw new Error(`Unable to login user ${error}`);
    }
  },
});

const signOut = schemaComposer.createResolver({
  name: "signOut",
  type: UserTC,
  kind: "mutation",
  args: {
    email: "String",
  },
  resolve: async ({ source, args, context, info }) => {
    try {
      const user = await UserModel.findOne({ email: args.email });
      if (!user) {
        throw new Error(`User with email: ${args.email} doesn't exist`);
      }

      user.set({ authToken: "", verificationToken: "" });
      await user.save();

      return;
    } catch (error) {
      throw new Error(`Unable to logout user ${error}`);
    }
  },
});

const AuthResolvers = {
  Mutation: {
    signUp,
    signIn,
    signOut,
    twoFactorVerification,
  },
};

export default AuthResolvers;
