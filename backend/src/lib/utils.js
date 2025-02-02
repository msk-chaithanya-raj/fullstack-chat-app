import jwt from "jsonwebtoken";
export const generateToken = async (userId, res) => {
  const token = await jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("jwt", token, {
    maxAge: 7 * 24 * 60 * 60 * 1000, // milliseconds MS
    httpOnly: true, // prevent XSS attacks and cross-orgin attacks
    sameSite: "strict", // prevents from CSRF attacks and cross-origin forgery attacks
    secure: process.env.NODE_ENV !== "development",
  });

  return token;
};
