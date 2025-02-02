import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token)
      return res
        .status(401)
        .json({ message: "Unauthorized - No Token Provided" });

    const decoded = await jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded)
      return res
        .status(401)
        .json({ message: "Unauthorized - No Token Provided" });

    const user = await User.findById(decoded.userId).select("-password");

    if (!user) return res.status(400).json({ message: "User not found" });

    req.user = user;
    next();
  } catch (error) {
    console.log("Error in proctected route middleware: ", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
