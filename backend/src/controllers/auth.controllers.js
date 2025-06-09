import bcrypt from "bcryptjs";
import User from "../models/user.model.js";
import { generateToken } from "../lib/utils.js";
import cloudinary from "../lib/cloudinary.js";

export const signup = async (req, res) => {
    const { fullName, email, password } = req.body;
    try {
        // Validate input fields
        if (!fullName || !email || !password) {
            return res.status(400).json({ message: "All fields must be provided!" });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters!" });
        }

        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already exists!" });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user instance
        const newUser = new User({
            fullName,
            email,
            password: hashedPassword,
        });

        // Save the new user and generate the JWT token
        await newUser.save();
        const token = generateToken(newUser._id, res); // Pass res if setting a cookie

        return res.status(201).json({
            message: "User created successfully!",
            _id: newUser._id,
            fullName: newUser.fullName,
            email: newUser.email,
            profilePic: newUser.profilePic || null,
            token, // Return the token in the response
        });
    } catch (error) {
        console.error("Error in signup controller:", error.message);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        // Validate input fields
        if (!email || !password) {
            return res.status(400).json({ message: "All fields must be provided!" });
        }

        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        // Verify the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials!" });
        }

        // Generate token and return user information
        const token = generateToken(user._id, res);
        return res.status(200).json({
            message: "Login successful!",
            _id: user._id,
            fullName: user.fullName,
            email: user.email,
            profilePic: user.profilePic || null,
            token,
        });
    } catch (error) {
        console.error("Error in login controller:", error.message);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const logout = (req, res) => {
    try {
        res.cookie("jwt", "", { maxAge: 0 }); // Expire the cookie
        return res.status(200).json({ message: "Logged out successfully!" });
    } catch (error) {
        console.error("Error in logout controller:", error.message);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const updateProfile = async (req, res) => {
    try {
        const { profilePic } = req.body;
        const userId = req.user._id;

        if (!profilePic) {
            return res.status(400).json({ message: "Profile picture is required" });
        }

        const uploadResponse = await cloudinary.uploader.upload(profilePic);
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { profilePic: uploadResponse.secure_url },
            { new: true }
        );

        return res.status(200).json(updatedUser);
    } catch (error) {
        console.error("Error in update profile:", error.message);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const checkAuth = (req,res)=>{
    try {
        res.status(200).json(req.user);
    } catch (error) {
        console.log("Error in checkAuth controller ",error.message);
        res.status(500).json({message:"Internal Server Error "});
        
    }

}

