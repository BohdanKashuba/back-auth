import { verifyJWT } from ".";
import UserModel from "../database/models/users.model";
import mongoose from "mongoose";

const verifyUser = async (bearerToken) => {
  try {
    if (!bearerToken) {
      return;
    }

    const token = bearerToken.replace(/^Bearer\s+/, "");
    const { data } = verifyJWT(token);
    if (!data) {
      return;
    }
    const _id = mongoose.Types.ObjectId(data.id);
    const user = await UserModel.findOne({
      $or: [{ email: data.email }, { _id }],
    });
    return user;
  } catch (err) {
    console.log(err);
    return false;
  }
};

export default verifyUser;
